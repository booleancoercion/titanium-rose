#![allow(clippy::large_enum_variant)]

use std::{sync::mpsc, thread};

use eframe::egui::{self, RichText, ViewportBuilder};
use titanium_rose::crypto::{
    elgamal::{Alice, Bob, BobEphemeral},
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
    WaitingForBob(Alice),
    Computing(mpsc::Receiver<SymmetricKey>),
    Final(SymmetricKey),
}

enum BobSetup {
    WaitingForAlice(Bob),
    Generating(Bob, mpsc::Receiver<BobEphemeral>),
    Final(Bob, BobEphemeral),
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
        egui::CentralPanel::default().show(ctx, |ui| match self {
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

                    ui.add_space(5.0);

                    if ui
                        .button(RichText::new("Continue New Session (Bob)").size(25.0))
                        .clicked()
                    {
                        // generating bob should be relatively cheap compared to alice
                        *self = MyEguiApp::BobSetup(BobSetup::WaitingForAlice(Bob::generate()));
                    }
                });
            }
            MyEguiApp::AliceSetup(AliceSetup::Generating(rx)) => {
                ui.horizontal(|ui| {
                    ui.heading("Please wait...");
                    ui.spinner();
                });

                match rx.try_recv() {
                    Ok(alice) => *self = MyEguiApp::AliceSetup(AliceSetup::WaitingForBob(alice)),
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
                }
            }
            MyEguiApp::BobSetup(_) => {
                ui.heading("Bob");
            }
            _ => {}
        });
    }
}
