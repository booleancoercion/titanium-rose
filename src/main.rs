#![allow(clippy::large_enum_variant)]

use std::env;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use eframe::egui::text::LayoutJob;
use eframe::egui::{self, Button, Galley, RichText, ScrollArea, Style, TextEdit, ViewportBuilder};

use titanium_rose::crypto::elgamal::{Alice, AlicePub, Bob, BobEphemeral};
use titanium_rose::crypto::SymmetricKey;

fn main() {
    let native_options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_resizable(false)
            .with_inner_size((500.0, 400.0)),
        ..Default::default()
    };

    eframe::run_native(
        "Titanium Rose",
        native_options,
        Box::new(|cc| Box::new(MyEguiApp::new(cc))),
    )
    .unwrap();
}

#[derive(Default)]
enum MyEguiApp {
    #[default]
    Initial,
    AliceSetup(AliceSetup),
    BobSetup(BobSetup),
    Final {
        encrypt_input: String,
        encrypt_output: String,
        encrypt_enabled: bool,
        encrypting: bool,
        encrypt_channel: (Sender<String>, Receiver<String>),

        decrypt_input: String,
        decrypt_output: String,
        decrypt_enabled: bool,
        decrypting: bool,
        failed_to_decrypt: bool,
        decrypt_channel: (Sender<String>, Receiver<Option<String>>),
    },
}

enum AliceSetup {
    Generating(mpsc::Receiver<Alice>),
    WaitingForBob(Alice, &'static str, String),
    Computing(mpsc::Receiver<SymmetricKey>),
}

enum BobSetup {
    WaitingForAlice(Bob, String),
    Generating(Bob, mpsc::Receiver<BobEphemeral>),
    Final(Bob, &'static str),
}

impl MyEguiApp {
    fn new(_: &eframe::CreationContext<'_>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        #[cfg(debug_assertions)]
        if env::var("SKIP_SETUP").is_ok() {
            return Self::new_final(SymmetricKey::generate());
        }

        Self::default()
    }

    fn new_final(key: SymmetricKey) -> Self {
        let (etx, remote_erx) = mpsc::channel();
        let (remote_etx, erx) = mpsc::channel();

        let ekey = key.clone();
        thread::spawn(move || loop {
            let input: String = remote_erx.recv().unwrap();
            let bytes = ekey.encrypt(input.as_bytes());
            let b64 = STANDARD_NO_PAD.encode(&bytes);
            remote_etx.send(b64).unwrap();
        });

        let (dtx, remote_drx) = mpsc::channel();
        let (remote_dtx, drx) = mpsc::channel();

        thread::spawn(move || loop {
            let input: String = remote_drx.recv().unwrap();
            let Ok(decoded) = STANDARD_NO_PAD.decode(input) else {
                remote_dtx.send(None).unwrap();
                continue;
            };

            let Some(plaintext) = key.decrypt(&decoded) else {
                remote_dtx.send(None).unwrap();
                continue;
            };

            if let Ok(string) = String::from_utf8(plaintext) {
                remote_dtx.send(Some(string)).unwrap();
            } else {
                remote_dtx.send(None).unwrap();
            }
        });

        Self::Final {
            encrypt_input: String::new(),
            encrypt_output: String::new(),
            encrypt_enabled: true,
            encrypting: false,
            encrypt_channel: (etx, erx),

            decrypt_input: String::new(),
            decrypt_output: String::new(),
            decrypt_enabled: true,
            decrypting: false,
            failed_to_decrypt: false,
            decrypt_channel: (dtx, drx),
        }
    }
}

const TEXT_DESIRED_ROWS: usize = 6;
const TEXT_SCROLLER_MAX_HEIGHT: f32 = 15.0 * (TEXT_DESIRED_ROWS as f32);

impl eframe::App for MyEguiApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.style_mut().spacing.item_spacing = (10.0, 10.0).into();

            match self {
                MyEguiApp::Initial => {
                    ui.vertical_centered_justified(|ui| {
                        if ui
                            .button(RichText::new("Start New Session (Alice)").size(25.0))
                            .clicked()
                        {
                            let (tx, rx) = mpsc::channel();
                            thread::spawn(move || {
                                let alice = Alice::generate();
                                tx.send(alice).unwrap()
                            });
                            *self = MyEguiApp::AliceSetup(AliceSetup::Generating(rx));
                        }

                        if ui
                            .button(RichText::new("Continue New Session (Bob)").size(25.0))
                            .clicked()
                        {
                            // generating bob should be relatively cheap compared to alice
                            *self = MyEguiApp::BobSetup(BobSetup::WaitingForAlice(
                                Bob::generate(),
                                String::new(),
                            ));
                        }
                    });
                }
                MyEguiApp::AliceSetup(AliceSetup::Generating(rx)) => {
                    ui.horizontal(|ui| {
                        ui.heading("Please wait...");
                        ui.spinner();
                    });

                    match rx.try_recv() {
                        Ok(alice) => {
                            let bytes = bincode::serialize(alice.get_public()).unwrap();
                            let public_text = STANDARD_NO_PAD.encode(bytes);
                            *self = MyEguiApp::AliceSetup(AliceSetup::WaitingForBob(
                                alice,
                                public_text.leak(),
                                String::new(),
                            ))
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                    }
                }
                MyEguiApp::AliceSetup(AliceSetup::WaitingForBob(alice, public_text, input)) => {
                    ui.heading("Copy your public key and send it to Bob:");

                    ScrollArea::vertical()
                        .id_source("first scroll area")
                        .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                        .show(ui, |ui| {
                            TextEdit::multiline(public_text)
                                .desired_rows(TEXT_DESIRED_ROWS)
                                .layouter(&mut my_layouter)
                                .show(ui);
                        });

                    ui.heading("Enter Bob's response:");

                    ScrollArea::vertical()
                        .id_source("second scroll area")
                        .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                        .show(ui, |ui| {
                            TextEdit::multiline(input)
                                .desired_rows(TEXT_DESIRED_ROWS)
                                .layouter(&mut my_layouter)
                                .show(ui);
                        });

                    if ui.button("Continue").clicked() {
                        // TODO: verify input correctness
                        let bytes = STANDARD_NO_PAD.decode(input).unwrap();
                        let eph: BobEphemeral = bincode::deserialize(&bytes).unwrap();

                        let (tx, rx) = mpsc::channel();
                        let alice = alice.clone();
                        thread::spawn(move || {
                            let secret = alice.extract_shared_secret(eph);
                            tx.send(secret).unwrap();
                        });

                        *self = MyEguiApp::AliceSetup(AliceSetup::Computing(rx));
                    }
                }
                MyEguiApp::AliceSetup(AliceSetup::Computing(rx)) => {
                    ui.horizontal(|ui| {
                        ui.heading("Please wait...");
                        ui.spinner();
                    });

                    match rx.try_recv() {
                        Ok(key) => *self = MyEguiApp::new_final(key),
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                    }
                }
                MyEguiApp::BobSetup(BobSetup::WaitingForAlice(bob, input)) => {
                    ui.heading("Enter Alice's public key:");

                    ScrollArea::vertical()
                        .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                        .show(ui, |ui| {
                            TextEdit::multiline(input)
                                .desired_rows(TEXT_DESIRED_ROWS)
                                .layouter(&mut my_layouter)
                                .show(ui);
                        });

                    if ui.button("Continue").clicked() {
                        // TODO: verify input correctness
                        let bytes = STANDARD_NO_PAD.decode(input).unwrap();
                        let public: AlicePub = bincode::deserialize(&bytes).unwrap();

                        let (tx, rx) = mpsc::channel();
                        {
                            let bob = bob.clone();
                            thread::spawn(move || {
                                let eph = bob.encrypt_for_alice(&public);
                                tx.send(eph).unwrap();
                            });
                        }

                        *self = MyEguiApp::BobSetup(BobSetup::Generating(bob.clone(), rx));
                    }
                }
                MyEguiApp::BobSetup(BobSetup::Generating(bob, rx)) => {
                    ui.horizontal(|ui| {
                        ui.heading("Please wait...");
                        ui.spinner();
                    });

                    match rx.try_recv() {
                        Ok(eph) => {
                            let bytes = bincode::serialize(&eph).unwrap();
                            let text = STANDARD_NO_PAD.encode(bytes).leak();
                            *self = MyEguiApp::BobSetup(BobSetup::Final(bob.clone(), text))
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                    }
                }
                MyEguiApp::BobSetup(BobSetup::Final(bob, text)) => {
                    ui.heading("Send the encrypted shared secret to Alice:");
                    ScrollArea::vertical()
                        .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                        .show(ui, |ui| {
                            TextEdit::multiline(text)
                                .desired_rows(TEXT_DESIRED_ROWS)
                                .layouter(&mut my_layouter)
                                .show(ui);
                        });

                    if ui.button("Continue").clicked() {
                        let key = bob.extract_shared_secret();
                        *self = MyEguiApp::new_final(key);
                    }
                }
                MyEguiApp::Final {
                    encrypt_input,
                    encrypt_output,
                    encrypt_enabled,
                    encrypting,
                    encrypt_channel,

                    decrypt_input,
                    decrypt_output,
                    decrypt_enabled,
                    decrypting,
                    failed_to_decrypt,
                    decrypt_channel,
                } => {
                    if *encrypting {
                        match encrypt_channel.1.try_recv() {
                            Ok(string) => {
                                *encrypt_output = string;
                                *encrypting = false
                            }
                            Err(mpsc::TryRecvError::Empty) => {}
                            Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                        }
                    }

                    if *decrypting {
                        match decrypt_channel.1.try_recv() {
                            Ok(Some(string)) => {
                                *decrypt_output = string;
                                *decrypting = false
                            }
                            Ok(None) => {
                                *decrypting = false;
                                *failed_to_decrypt = true;
                            }
                            Err(mpsc::TryRecvError::Empty) => {}
                            Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                        }
                    }

                    ui.columns(2, |columns| {
                        columns[0].heading("Encrypt Text");
                        let encrypt_input_response = ScrollArea::vertical()
                            .id_source("encrypt input")
                            .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                            .show(&mut columns[0], |ui| {
                                ui.add_enabled(
                                    !*encrypting,
                                    TextEdit::multiline(encrypt_input)
                                        .desired_rows(TEXT_DESIRED_ROWS)
                                        .layouter(&mut my_layouter),
                                )
                            })
                            .inner;

                        if encrypt_input_response.changed() {
                            encrypt_output.clear();
                            *encrypt_enabled = true;
                        }

                        ScrollArea::vertical()
                            .id_source("encrypt output")
                            .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                            .show(&mut columns[0], |ui| {
                                TextEdit::multiline(&mut encrypt_output.as_str())
                                    .desired_rows(TEXT_DESIRED_ROWS)
                                    .layouter(&mut my_layouter)
                                    .show(ui)
                                    .response
                            });

                        let encrypt_button =
                            columns[0].add_enabled(*encrypt_enabled, Button::new("Encrypt"));

                        if encrypt_button.clicked() {
                            *encrypt_enabled = false;
                            *encrypting = true;
                            encrypt_channel.0.send(encrypt_input.clone()).unwrap();
                        }

                        if *encrypting {
                            columns[0].spinner();
                        }

                        columns[1].heading("Decrypt Text");
                        let decrypt_input_response = ScrollArea::vertical()
                            .id_source("decrypt input")
                            .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                            .show(&mut columns[1], |ui| {
                                ui.add_enabled(
                                    !*decrypting,
                                    TextEdit::multiline(decrypt_input)
                                        .desired_rows(TEXT_DESIRED_ROWS)
                                        .layouter(&mut my_layouter),
                                )
                            })
                            .inner;

                        if decrypt_input_response.changed() {
                            decrypt_output.clear();
                            *decrypt_enabled = true;
                            *failed_to_decrypt = false;
                        }

                        ScrollArea::vertical()
                            .id_source("decrypt output")
                            .max_height(TEXT_SCROLLER_MAX_HEIGHT)
                            .show(&mut columns[1], |ui| {
                                TextEdit::multiline(&mut decrypt_output.as_str())
                                    .desired_rows(TEXT_DESIRED_ROWS)
                                    .layouter(&mut my_layouter)
                                    .show(ui)
                                    .response
                            });

                        let decrypt_button =
                            columns[1].add_enabled(*decrypt_enabled, Button::new("Decrypt"));

                        if decrypt_button.clicked() {
                            *decrypt_enabled = false;
                            *decrypting = true;
                            decrypt_channel.0.send(decrypt_input.clone()).unwrap();
                        }

                        if *decrypting {
                            columns[1].spinner();
                        }
                        if *failed_to_decrypt {
                            columns[1].label("failed to decrypt");
                        }
                    });
                }
            }
        });
    }
}

fn my_layouter(ui: &egui::Ui, string: &str, wrap_width: f32) -> Arc<Galley> {
    let mut layout_job: egui::text::LayoutJob = LayoutJob::default();

    // why do i have to get an entire layouter just to do this??
    layout_job.wrap.break_anywhere = true;

    layout_job.wrap.max_width = wrap_width;
    RichText::new(string).monospace().append_to(
        &mut layout_job,
        &Style::default(),
        egui::FontSelection::Default,
        egui::Align::Center,
    );
    ui.fonts(|f| f.layout_job(layout_job))
}
