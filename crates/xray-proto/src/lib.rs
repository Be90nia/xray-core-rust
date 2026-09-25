pub mod xray {
    pub mod common {
        pub mod net {
            include!(concat!(env!("OUT_DIR"), "/xray.common.net.rs"));
        }
        pub mod protocol {
            include!(concat!(env!("OUT_DIR"), "/xray.common.protocol.rs"));
        }
        pub mod serial {
            include!(concat!(env!("OUT_DIR"), "/xray.common.serial.rs"));
        }
        pub mod log {
            include!(concat!(env!("OUT_DIR"), "/xray.common.log.rs"));
        }
        pub mod geodata {
            include!(concat!(env!("OUT_DIR"), "/xray.common.geodata.rs"));
        }
    }

    pub mod core {
        include!(concat!(env!("OUT_DIR"), "/xray.core.rs"));

        pub mod app {
            pub mod observatory {
                include!(concat!(env!("OUT_DIR"), "/xray.core.app.observatory.rs"));

                pub mod burst {
                    include!(concat!(env!("OUT_DIR"), "/xray.core.app.observatory.burst.rs"));
                }
                pub mod command {
                    include!(concat!(env!("OUT_DIR"), "/xray.core.app.observatory.command.rs"));
                }
            }
        }
    }

    pub mod app {
        pub mod commander {
            include!(concat!(env!("OUT_DIR"), "/xray.app.commander.rs"));
        }
        pub mod dispatcher {
            include!(concat!(env!("OUT_DIR"), "/xray.app.dispatcher.rs"));
        }
        pub mod dns {
            include!(concat!(env!("OUT_DIR"), "/xray.app.dns.rs"));

            pub mod fakedns {
                include!(concat!(env!("OUT_DIR"), "/xray.app.dns.fakedns.rs"));
            }
        }
        pub mod geodata {
            include!(concat!(env!("OUT_DIR"), "/xray.app.geodata.rs"));
        }
        pub mod log {
            include!(concat!(env!("OUT_DIR"), "/xray.app.log.rs"));

            pub mod command {
                include!(concat!(env!("OUT_DIR"), "/xray.app.log.command.rs"));
            }
        }
        pub mod metrics {
            include!(concat!(env!("OUT_DIR"), "/xray.app.metrics.rs"));
        }
        pub mod policy {
            include!(concat!(env!("OUT_DIR"), "/xray.app.policy.rs"));
        }
        pub mod proxyman {
            include!(concat!(env!("OUT_DIR"), "/xray.app.proxyman.rs"));

            pub mod command {
                include!(concat!(env!("OUT_DIR"), "/xray.app.proxyman.command.rs"));
            }
        }
        pub mod reverse {
            include!(concat!(env!("OUT_DIR"), "/xray.app.reverse.rs"));
        }
        pub mod router {
            include!(concat!(env!("OUT_DIR"), "/xray.app.router.rs"));

            pub mod command {
                include!(concat!(env!("OUT_DIR"), "/xray.app.router.command.rs"));
            }
        }
        pub mod stats {
            include!(concat!(env!("OUT_DIR"), "/xray.app.stats.rs"));

            pub mod command {
                include!(concat!(env!("OUT_DIR"), "/xray.app.stats.command.rs"));
            }
        }
        pub mod version {
            include!(concat!(env!("OUT_DIR"), "/xray.app.version.rs"));
        }
    }

    pub mod proxy {
        pub mod vless {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.rs"));

            pub mod encoding {
                include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.encoding.rs"));
            }
            pub mod inbound {
                include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.inbound.rs"));
            }
            pub mod outbound {
                include!(concat!(env!("OUT_DIR"), "/xray.proxy.vless.outbound.rs"));
            }
        }
        pub mod vmess {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.vmess.rs"));

            pub mod inbound {
                include!(concat!(env!("OUT_DIR"), "/xray.proxy.vmess.inbound.rs"));
            }
            pub mod outbound {
                include!(concat!(env!("OUT_DIR"), "/xray.proxy.vmess.outbound.rs"));
            }
        }
        pub mod shadowsocks {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.shadowsocks.rs"));
        }
        pub mod shadowsocks_2022 {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.shadowsocks_2022.rs"));
        }
        pub mod trojan {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.trojan.rs"));
        }
        pub mod socks {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.socks.rs"));
        }
        pub mod http {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.http.rs"));
        }
        pub mod dns {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.dns.rs"));
        }
        pub mod blackhole {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.blackhole.rs"));
        }
        pub mod freedom {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.freedom.rs"));
        }
        pub mod dokodemo {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.dokodemo.rs"));
        }
        pub mod loopback {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.loopback.rs"));
        }
        pub mod tun {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.tun.rs"));
        }
        pub mod wireguard {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.wireguard.rs"));
        }
        pub mod hysteria {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.hysteria.rs"));

            pub mod account {
                include!(concat!(env!("OUT_DIR"), "/xray.proxy.hysteria.account.rs"));
            }
        }
    }

    pub mod transport {
        pub mod internet {
            include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.rs"));

            pub mod grpc {
                pub mod encoding {
                    include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.grpc.encoding.rs"));
                }
            }
            pub mod headers {
                pub mod http {
                    include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.headers.http.rs"));
                }
                pub mod noop {
                    include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.headers.noop.rs"));
                }
            }
            pub mod finalmask {
                pub mod fragment {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.fragment.rs"
                    ));
                }
                pub mod header {
                    pub mod custom {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/xray.transport.internet.finalmask.header.custom.rs"
                        ));
                    }
                }
                pub mod mkcp {
                    pub mod aes128gcm {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/xray.transport.internet.finalmask.mkcp.aes128gcm.rs"
                        ));
                    }
                    pub mod header {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/xray.transport.internet.finalmask.mkcp.header.rs"
                        ));
                    }
                    pub mod original {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/xray.transport.internet.finalmask.mkcp.original.rs"
                        ));
                    }
                }
                pub mod noise {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.noise.rs"
                    ));
                }
                pub mod realm {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.realm.rs"
                    ));
                }
                pub mod salamander {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.salamander.rs"
                    ));
                }
                pub mod sudoku {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.sudoku.rs"
                    ));
                }
                pub mod xdns {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.xdns.rs"
                    ));
                }
                pub mod xicmp {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.xicmp.rs"
                    ));
                }
            }
            pub mod httpupgrade {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.httpupgrade.rs"));
            }
            pub mod hysteria {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.hysteria.rs"));
            }
            pub mod kcp {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.kcp.rs"));
            }
            pub mod reality {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.reality.rs"));
            }
            pub mod splithttp {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.splithttp.rs"));
            }
            pub mod tcp {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.tcp.rs"));
            }
            pub mod tls {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.tls.rs"));
            }
            pub mod udp {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.udp.rs"));
            }
            pub mod websocket {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.websocket.rs"));
            }
        }
    }
}

/// 全量 `FileDescriptorSet` 编码字节（grpc-client/grpc-server 构建时生成）。
///
/// 供 tonic-reflection server（`register_encoded_file_descriptor_set`）注册，
/// 使 gRPC 客户端（grpcurl / CLI）可发现全部服务。
#[cfg(any(feature = "grpc-client", feature = "grpc-server"))]
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/xray_descriptor.bin"));

pub use xray::*;
