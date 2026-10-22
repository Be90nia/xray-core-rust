#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
// 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
// 生成代码（tonic server traits）经 async-trait 脱糖后带 #[must_use]，clippy 1.99 起
// double_must_use 命中；仅本 crate（纯 include! 生成物）豁免。
#![allow(clippy::double_must_use)]

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
        // 生成代码 xray.app.policy.rs 内部再开 `pub mod policy`（prost 按Go 包
        // 名嵌套），与外层模块同名——protobuf 布局如此，非手写失误。
        #[allow(clippy::module_inception)] // prost 按 Go 包名生成嵌套 policy::policy，布局如此
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
        pub mod masque {
            include!(concat!(env!("OUT_DIR"), "/xray.proxy.masque.rs"));
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
                pub mod udphop {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/xray.transport.internet.finalmask.udphop.rs"
                    ));
                }
                pub mod xmc {
                    include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.finalmask.xmc.rs"));
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
            pub mod masque {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.masque.rs"));
            }
            pub mod xdrive {
                include!(concat!(env!("OUT_DIR"), "/xray.transport.internet.xdrive.rs"));
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

/// G7 proto 对齐回归（票 Xray-core-rust-5std）：样本字节由 Go wire 编码器
/// （protoc --encode，与 Go protobuf 运行时同编码）产出，字段含对账报告
/// 原「Go→Rust 静默丢」项。解码必须还原字段值，而非报错或静默丢弃。
#[cfg(test)]
mod g7_proto_parity_tests {
    use prost::Message;

    #[test]
    fn loopback_sniffing_survives_go_wire_decode() {
        // inbound_tag:"in-loopback" + sniffing{enabled, dest_override:[http,tls], route_only}
        let wire: &[u8] = &[
            0x0a, 0x0b, 0x69, 0x6e, 0x2d, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b, //
            0x12, 0x0f, 0x08, 0x01, 0x12, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x03, 0x74, 0x6c,
            0x73, 0x28, 0x01,
        ];
        let cfg = crate::xray::proxy::loopback::Config::decode(wire).unwrap();
        assert_eq!(cfg.inbound_tag, "in-loopback");
        let sniffing = cfg.sniffing.expect("Go tag2 sniffing 必须还原（对齐前静默丢）");
        assert!(sniffing.enabled);
        assert_eq!(sniffing.destination_override, vec!["http", "tls"]);
        assert!(sniffing.route_only);
    }

    #[test]
    fn dns_id_and_script_survive_go_wire_decode() {
        // name_server[0].id:"ns-primary"（tag18）+ script:"lua://handler"（tag15）
        let wire: &[u8] = &[
            0x2a, 0x0d, 0x92, 0x01, 0x0a, 0x6e, 0x73, 0x2d, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72,
            0x79, 0x7a, 0x0d, 0x6c, 0x75, 0x61, 0x3a, 0x2f, 0x2f, 0x68, 0x61, 0x6e, 0x64, 0x6c,
            0x65, 0x72,
        ];
        let cfg = crate::xray::app::dns::Config::decode(wire).unwrap();
        assert_eq!(cfg.name_server[0].id, "ns-primary");
        assert_eq!(cfg.script, "lua://handler");
    }

    #[test]
    fn tun_new_fields_survive_go_wire_decode() {
        // name:"tun0" + desc:"prod-tunnel"(tag8) + auto_system_dns_to_gateway(tag9)
        // + auto_system_wfp_block_leak:["4242","4243"](tag10)
        let wire: &[u8] = &[
            0x0a, 0x04, 0x74, 0x75, 0x6e, 0x30, 0x42, 0x0b, 0x70, 0x72, 0x6f, 0x64, 0x2d, 0x74,
            0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x48, 0x01, 0x52, 0x04, 0x34, 0x32, 0x34, 0x32, 0x52,
            0x04, 0x34, 0x32, 0x34, 0x33,
        ];
        let cfg = crate::xray::proxy::tun::Config::decode(wire).unwrap();
        assert_eq!(cfg.desc, "prod-tunnel");
        assert!(cfg.auto_system_dns_to_gateway);
        assert_eq!(cfg.auto_system_wfp_block_leak, vec!["4242", "4243"]);
    }
}
