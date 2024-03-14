#![allow(clippy::large_enum_variant)]

use std::{
    sync::{mpsc, Arc},
    thread,
};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use eframe::egui::{
    self, text::LayoutJob, Galley, RichText, ScrollArea, Style, TextEdit, ViewportBuilder,
};
use titanium_rose::crypto::{
    elgamal::{Alice, AlicePub, Bob, BobEphemeral},
    SymmetricKey,
};

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
    Final(SymmetricKey),
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
        Self::default()
    }
}

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
                        .max_height(100.0)
                        .show(ui, |ui| {
                            TextEdit::multiline(public_text)
                                .layouter(&mut my_layouter)
                                .show(ui);
                        });

                    ui.heading("Enter Bob's response:");

                    ScrollArea::vertical()
                        .id_source("second scroll area")
                        .max_height(100.0)
                        .show(ui, |ui| {
                            TextEdit::multiline(input)
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
                        Ok(key) => *self = MyEguiApp::Final(key),
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                    }
                }
                MyEguiApp::BobSetup(BobSetup::WaitingForAlice(bob, input)) => {
                    ui.heading("Enter Alice's public key:");

                    ScrollArea::vertical()
                        .id_source("second scroll area")
                        .max_height(100.0)
                        .show(ui, |ui| {
                            TextEdit::multiline(input)
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
                    ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                        TextEdit::multiline(text)
                            .layouter(&mut my_layouter)
                            .show(ui);
                    });

                    if ui.button("Continue").clicked() {
                        let key = bob.extract_shared_secret();
                        *self = MyEguiApp::Final(key);
                    }
                }
                MyEguiApp::Final(key) => {
                    //
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
