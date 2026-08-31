//! # XMC 26.1.2 padding preset（对应 Go `xmc/padding_preset.go`）
//!
//! 把 Go 的 6 turn 启动阶段 + 32 turn play_join 阶段模板连同 burst/branch
//! 调度一起镜像到 Rust。`new_client_padding_schedule_2612` 与
//! `new_server_padding_schedule_2612` 返回的 schedule 喂给
//! `padding::run_padding_schedule` 即可。

use std::io;

use super::padding::{
    PaddingDelayRange, PaddingDirection, PaddingTurn, PaddingVariant,
};

/// 区间长度（对应 Go `paddingLengthRange2612`）。
#[derive(Debug, Clone, Copy)]
pub struct PaddingLengthRange {
    pub minimum: i32,
    pub maximum: i32,
}

/// 服务端 play 阶段 small/large 分支（对应 Go `serverPlayLengthBranches2612`）。
#[derive(Debug, Clone, Copy)]
pub struct ServerPlayLengthBranches {
    pub small: PaddingLengthRange,
    pub large: PaddingLengthRange,
}

/// 客户端 play 阶段常规 + burst 分支（对应 Go `clientPlayBurst2612`）。
#[derive(Debug, Clone, Copy)]
pub struct ClientPlayBurst {
    pub play_index: usize,
    pub regular: PaddingLengthRange,
    pub burst: PaddingLengthRange,
}

fn millisecond_range(minimum: u64, maximum: u64) -> PaddingDelayRange {
    PaddingDelayRange::from_millis(minimum, maximum)
}

fn variant_from_chunks(chunks: &[i32]) -> PaddingVariant {
    PaddingVariant {
        chunks: chunks.to_vec(),
        delays: Vec::new(),
    }
}

fn paced_variant(chunks: &[i32], pauses: &[(usize, PaddingDelayRange)]) -> PaddingVariant {
    let mut delays = vec![PaddingDelayRange::ZERO; chunks.len()];
    for (chunk, delay) in pauses {
        if *chunk >= delays.len() {
            panic!("xmc: padding pause index is outside its chunk template");
        }
        delays[*chunk] = *delay;
    }
    PaddingVariant {
        chunks: chunks.to_vec(),
        delays,
    }
}

fn registry_padding_variant() -> PaddingVariant {
    paced_variant(
        &[
            1590, 226, 329, 229, 186, 151, 78, 81, 79, 235, 67, 67, 78, 71, 82, 74, 982, 117, 1118,
            1038, 970, 400, 239, 49, 50, 95, 65, 104, 32320, 2,
        ],
        &[
            (28, millisecond_range(1, 4)),
            (29, millisecond_range(44, 61)),
        ],
    )
}

fn play_start_padding_variant(chunks: &[i32]) -> PaddingVariant {
    if chunks.len() < 2 {
        panic!("xmc: play start padding variant needs at least two chunks");
    }
    let mid = chunks.len() / 2;
    let last = chunks.len() - 1;
    paced_variant(
        chunks,
        &[
            (mid, millisecond_range(1, 5)),
            (last, millisecond_range(9, 20)),
        ],
    )
}

/// 启动 6 turn 模板（client→server / server→client 交替，对应 Go `startupPaddingSchedule2612`）。
pub fn startup_padding_schedule_2612() -> Vec<PaddingTurn> {
    vec![
        PaddingTurn {
            direction: PaddingDirection::ClientToServer,
            variants: vec![variant_from_chunks(&[2, 26, 16])],
            ..PaddingTurn::default()
        },
        PaddingTurn {
            direction: PaddingDirection::ServerToClient,
            variants: vec![variant_from_chunks(&[26, 21, 25])],
            start_delay: millisecond_range(0, 20),
            ..PaddingTurn::default()
        },
        PaddingTurn {
            direction: PaddingDirection::ClientToServer,
            variants: vec![variant_from_chunks(&[25])],
            start_delay: millisecond_range(2, 22),
            ..PaddingTurn::default()
        },
        PaddingTurn {
            direction: PaddingDirection::ServerToClient,
            variants: vec![registry_padding_variant()],
            start_delay: millisecond_range(20, 50),
            ..PaddingTurn::default()
        },
        PaddingTurn {
            direction: PaddingDirection::ClientToServer,
            variants: vec![variant_from_chunks(&[2])],
            start_delay: millisecond_range(10, 35),
            ..PaddingTurn::default()
        },
        PaddingTurn {
            direction: PaddingDirection::ServerToClient,
            variants: vec![
                play_start_padding_variant(&[
                    4941, 252, 259, 267, 268, 251, 303, 259, 264, 54, 346,
                ]),
                play_start_padding_variant(&[
                    4941, 262, 284, 272, 260, 260, 313, 264, 151, 224, 207, 215, 224, 390,
                ]),
                play_start_padding_variant(&[
                    4941, 257, 272, 275, 260, 260, 313, 283, 274, 226, 207, 230, 215, 204, 221,
                    352,
                ]),
                play_start_padding_variant(&[
                    4941, 259, 272, 288, 260, 260, 311, 270, 70, 236, 223, 201, 210, 352,
                ]),
                play_start_padding_variant(&[
                    4941, 255, 269, 277, 263, 260, 136, 207, 210, 232, 325,
                ]),
                play_start_padding_variant(&[
                    4941, 259, 270, 274, 263, 258, 327, 170, 210, 375,
                ]),
                play_start_padding_variant(&[
                    4941, 257, 275, 291, 260, 260, 325, 269, 70, 230, 226, 207, 221, 352,
                ]),
                play_start_padding_variant(&[4941, 252, 273, 262, 252, 254, 306, 93]),
                play_start_padding_variant(&[
                    4941, 273, 270, 269, 258, 256, 322, 221, 207, 215, 438,
                ]),
                play_start_padding_variant(&[
                    4941, 259, 275, 274, 250, 258, 308, 267, 154, 233, 209, 207, 213, 393,
                ]),
                play_start_padding_variant(&[
                    4941, 254, 267, 272, 260, 253, 311, 167, 204, 232, 207, 481, 8,
                ]),
                play_start_padding_variant(&[
                    4941, 259, 269, 272, 261, 313, 207, 213, 500, 19,
                ]),
                play_start_padding_variant(&[
                    4941, 262, 269, 274, 263, 274, 311, 270, 242, 210, 229, 221, 210, 431,
                ]),
                play_start_padding_variant(&[
                    4941, 259, 265, 277, 263, 277, 316, 269, 156, 204, 210, 226, 207, 413,
                ]),
                play_start_padding_variant(&[
                    4941, 215, 251, 249, 317, 260, 270, 249, 52,
                ]),
                play_start_padding_variant(&[
                    4941, 224, 263, 277, 316, 267, 272, 260, 138, 230, 226, 207, 204, 352,
                ]),
                play_start_padding_variant(&[
                    4941, 221, 258, 263, 319, 269, 288, 263, 136, 204, 210, 220, 207, 378,
                ]),
                play_start_padding_variant(&[
                    4941, 221, 258, 260, 316, 273, 291, 226, 204, 229, 213, 489, 8,
                ]),
                play_start_padding_variant(&[
                    4941, 238, 260, 261, 306, 272, 277, 260, 224, 241, 212, 207, 204, 393,
                ]),
                play_start_padding_variant(&[
                    4941, 224, 260, 260, 309, 272, 277, 277, 138, 207, 207, 212, 241, 352,
                ]),
            ],
            start_delay: millisecond_range(35, 50),
            ..PaddingTurn::default()
        },
    ]
}

/// play_join 阶段 32 turn 模板（17 client + 15 server 交替，
/// 对应 Go `playJoinPaddingSchedule2612`）。
pub fn play_join_padding_schedule_2612() -> Vec<PaddingTurn> {
    let mut out = Vec::with_capacity(32);
    let client_min_max: &[(i32, i32)] = &[
        (6, 883),
        (6, 887),
        (2, 50),
        (6, 45),
        (2, 44),
        (2, 851),
        (2, 19),
        (8, 24),
        (2, 19),
        (6, 19),
        (6, 19),
        (2, 19),
        (6, 19),
        (8, 43),
        (2, 19),
        (5, 19),
        (6, 19),
    ];
    let server_min_max: &[(i32, i32)] = &[
        (346, 58638),
        (388, 61077),
        (575, 65584),
        (86, 63563),
        (42, 51983),
        (309, 25083),
        (74, 63885),
        (30, 66128),
        (26, 35818),
        (35, 59407),
        (37, 65328),
        (26, 60622),
        (11, 60808),
        (55, 62027),
        (427, 65622),
        (35, 59401),
    ];
    for (c, s) in client_min_max.iter().zip(server_min_max.iter()) {
        out.push(client_play_padding_turn(c.0, c.1));
        out.push(server_play_padding_turn(s.0, s.1));
    }
    out.push(client_play_padding_turn(6, 19));
    out
}

/// 完整 2612 schedule：startup + play_join（对应 Go `paddingSchedule2612`）。
pub fn padding_schedule_2612() -> Vec<PaddingTurn> {
    let mut out = startup_padding_schedule_2612();
    out.extend(play_join_padding_schedule_2612());
    out
}

fn client_play_padding_turn(minimum: i32, maximum: i32) -> PaddingTurn {
    PaddingTurn {
        direction: PaddingDirection::ClientToServer,
        min_length: minimum,
        max_length: maximum,
        start_delay: millisecond_range(1, 30),
        write_chunk_length: 1024,
        ..PaddingTurn::default()
    }
}

fn server_play_padding_turn(minimum: i32, maximum: i32) -> PaddingTurn {
    PaddingTurn {
        direction: PaddingDirection::ServerToClient,
        min_length: minimum,
        max_length: maximum,
        start_delay: millisecond_range(1, 45),
        chunk_delay: millisecond_range(1, 4),
        write_chunk_min_length: 32 * 1024,
        write_chunk_length: super::padding::MAX_PADDING_CHUNK_LENGTH,
        ..PaddingTurn::default()
    }
}

fn client_play_bursts_2612() -> [ClientPlayBurst; 3] {
    [
        ClientPlayBurst {
            play_index: 0,
            regular: PaddingLengthRange { minimum: 6, maximum: 44 },
            burst: PaddingLengthRange { minimum: 877, maximum: 883 },
        },
        ClientPlayBurst {
            play_index: 2,
            regular: PaddingLengthRange { minimum: 6, maximum: 45 },
            burst: PaddingLengthRange { minimum: 884, maximum: 887 },
        },
        ClientPlayBurst {
            play_index: 10,
            regular: PaddingLengthRange { minimum: 2, maximum: 19 },
            burst: PaddingLengthRange { minimum: 851, maximum: 851 },
        },
    ]
}

fn client_play_burst_choices_2612() -> Vec<usize> {
    let mut v = vec![0usize; 17];
    v.push(1);
    v.push(1);
    v.push(2);
    v
}

fn server_play_branches_2612() -> Vec<ServerPlayLengthBranches> {
    vec![
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 346, maximum: 18812 },
            large: PaddingLengthRange { minimum: 51702, maximum: 58638 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 388, maximum: 20689 },
            large: PaddingLengthRange { minimum: 51445, maximum: 61077 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 575, maximum: 20915 },
            large: PaddingLengthRange { minimum: 41428, maximum: 65584 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 86, maximum: 2772 },
            large: PaddingLengthRange { minimum: 41428, maximum: 63563 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 42, maximum: 26813 },
            large: PaddingLengthRange { minimum: 51983, maximum: 51983 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 309, maximum: 19484 },
            large: PaddingLengthRange { minimum: 24837, maximum: 25083 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 74, maximum: 40686 },
            large: PaddingLengthRange { minimum: 63885, maximum: 63885 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 30, maximum: 44114 },
            large: PaddingLengthRange { minimum: 66128, maximum: 66128 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 26, maximum: 1464 },
            large: PaddingLengthRange { minimum: 9941, maximum: 35818 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 35, maximum: 42885 },
            large: PaddingLengthRange { minimum: 52194, maximum: 59407 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 37, maximum: 47553 },
            large: PaddingLengthRange { minimum: 61765, maximum: 65328 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 26, maximum: 1121 },
            large: PaddingLengthRange { minimum: 16162, maximum: 60622 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 11, maximum: 45629 },
            large: PaddingLengthRange { minimum: 60808, maximum: 60808 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 55, maximum: 10035 },
            large: PaddingLengthRange { minimum: 30237, maximum: 62027 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 427, maximum: 52536 },
            large: PaddingLengthRange { minimum: 64014, maximum: 65622 },
        },
        ServerPlayLengthBranches {
            small: PaddingLengthRange { minimum: 35, maximum: 22708 },
            large: PaddingLengthRange { minimum: 38987, maximum: 59401 },
        },
    ]
}

fn server_play_branch_masks_2612() -> Vec<u32> {
    vec![
        0x011c, 0x090a, 0x0821, 0xe921, 0x2102, 0x0844, 0xa101, 0x1106, 0x2e00, 0xab01, 0xe900,
        0xac01, 0xab01, 0x8b80, 0x0808, 0x2001, 0x0901, 0x000a, 0x2c01, 0x0801,
    ]
}

fn rand_index(length: usize) -> usize {
    if length == 0 {
        return 0;
    }
    if length == 1 {
        return 0;
    }
    (rand::random::<u32>() as usize) % length
}

/// 构造客户端 2612 schedule（对应 Go `newClientPaddingSchedule2612`）。
pub fn new_client_padding_schedule_2612() -> Result<Vec<PaddingTurn>, io::Error> {
    let choices = client_play_burst_choices_2612();
    let choice = rand_index(choices.len());
    let selected = choices[choice];
    let mut schedule = padding_schedule_2612();
    let bursts = client_play_bursts_2612();
    let startup_len = startup_padding_schedule_2612().len();
    for (i, burst) in bursts.iter().enumerate() {
        let length_range = if i == selected { burst.burst } else { burst.regular };
        let idx = startup_len + burst.play_index;
        if idx >= schedule.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("play index {} out of range", burst.play_index),
            ));
        }
        schedule[idx].send_min_length = length_range.minimum;
        schedule[idx].send_max_length = length_range.maximum;
    }
    Ok(schedule)
}

/// 构造服务端 2612 schedule（对应 Go `newServerPaddingSchedule2612`）。
pub fn new_server_padding_schedule_2612() -> Result<Vec<PaddingTurn>, io::Error> {
    let mut schedule = padding_schedule_2612();
    let profile_index = rand_index(server_play_branch_masks_2612().len());
    let profile = server_play_branch_masks_2612()[profile_index];
    let startup_len = startup_padding_schedule_2612().len();
    for (i, branches) in server_play_branches_2612().iter().enumerate() {
        let length_range = if profile & (1 << i) != 0 {
            branches.large
        } else {
            branches.small
        };
        let idx = startup_len + 1 + i * 2;
        if idx >= schedule.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("server branch index {} out of range", idx),
            ));
        }
        schedule[idx].send_min_length = length_range.minimum;
        schedule[idx].send_max_length = length_range.maximum;
    }
    Ok(schedule)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_has_six_turns() {
        let s = startup_padding_schedule_2612();
        assert_eq!(s.len(), 6);
        assert_eq!(s[0].direction, PaddingDirection::ClientToServer);
        assert_eq!(s[1].direction, PaddingDirection::ServerToClient);
    }
    #[test]
    fn full_2612_schedule_length_is_39() {
        let s = padding_schedule_2612();
        assert_eq!(s.len(), 39);
    }

    #[test]
    fn client_schedule_has_burst_send_ranges() {
        let s = new_client_padding_schedule_2612().unwrap();
        assert_eq!(s.len(), 39);
        // play_index 0 → schedule[6]; play_index 2 → schedule[8]; play_index 10 → schedule[16].
        // Send ranges always set regardless of which burst was selected.
        for idx in [6usize, 8, 16] {
            assert!(s[idx].send_min_length > 0);
            assert!(s[idx].send_max_length >= s[idx].send_min_length);
        }
    }

    #[test]
    fn server_schedule_has_branch_send_ranges() {
        let s = new_server_padding_schedule_2612().unwrap();
        assert_eq!(s.len(), 39);
        // server branches target odd play_join slots starting at schedule[7].
        for i in 0..server_play_branches_2612().len() {
            let idx = 6 + 1 + i * 2;
            assert!(s[idx].send_min_length > 0);
            assert!(s[idx].send_max_length >= s[idx].send_min_length);
        }
    }

    #[test]
    fn client_play_padding_turn_uses_write_chunk_1024() {
        let t = client_play_padding_turn(1, 100);
        assert_eq!(t.write_chunk_length, 1024);
        assert_eq!(t.direction, PaddingDirection::ClientToServer);
    }

    #[test]
    fn server_play_padding_turn_uses_max_chunk() {
        let t = server_play_padding_turn(100, 1000);
        assert_eq!(t.write_chunk_length, super::super::padding::MAX_PADDING_CHUNK_LENGTH);
        assert_eq!(t.write_chunk_min_length, 32 * 1024);
    }

    #[test]
    fn registry_variant_has_30_chunks_with_pauses() {
        let v = registry_padding_variant();
        assert_eq!(v.chunks.len(), 30);
        assert_eq!(v.delays.len(), 30);
        // pauses at chunk 28 and 29 → delays[28], delays[29] nonzero max.
        assert!(v.delays[28].max > std::time::Duration::ZERO);
        assert!(v.delays[29].max > std::time::Duration::ZERO);
    }
}
