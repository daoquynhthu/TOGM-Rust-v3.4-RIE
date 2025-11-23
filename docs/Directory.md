TOGM-Rust-v3.4-RIE/
├── Cargo.toml                      # 主配置：staticlib + rlib；features=["drand" (n≤50规模自适应), "i2p", "dbap" (三层认证), "paranoid" (dummy ops for timing), "watchdog" (异常监控)]；零 crypto deps
├── Cargo.lock                      # 锁定零外部 crypto 依赖，确保 ITS 纯度
├── build.rs                        # 构建脚本：LTO=thin + codegen-units=1 + native CPU；生成 genesis_hash.rs + 分段 HMAC 偏移常量 + 白皮书合规常量
├── .cargo/
│   └── config.toml                 # Release 强制：lto=thin, codegen-units=1, target-cpu=native, panic=abort；no_std 核心
├── src/
│   ├── lib.rs                      # Crate 入口：公开 API (<400 pub fn)；全局状态机初始化 (state_machine.rs)；DBAP 状态检查 + Iron Laws 入口
│   ├── core/                       # 纯数学核心 (no_std + zeroize, <6000 LOC 等价)：无 PRNG/PRF/XOF 依赖，iron_laws.rs 强制执行
│   │   ├── mod.rs
│   │   ├── xor.rs                  # SIMD-optimized XOR (千兆级, const generics + 标量 fallback；白皮书 1.1/7.1)
│   │   ├── gf256.rs                # GF(2^8) 全表格 (const 数组, 零分支, 常数时间；用于 BGW/SIP；白皮书 1.1/1.2)
│   │   ├── universal_hash.rs       # Toeplitz extractor (Leftover Hash Lemma 证明, GF(2^8)-based；白皮书 1.1/5)
│   │   ├── sip64.rs                # 64B information-theoretic SIP MAC (Poly1305-style over GF(2^8)；白皮书 1.2/7.1)
│   │   ├── otp_engine.rs           # 4096B block 纯 OTP (常数时间 XOR + SIP 标签；白皮书 7.1, Listing 1)
│   │   ├── masterpad.rs            # Gigabyte mmap 管理 (memmap2, 只驻留当前±1 block + madvise 非驻留；白皮书 1.1/1.2)
│   │   └── ratchet.rs              # Ratchet 触发 (<20% 阈值自动 re-bootstrap) + 块 ID 原子推进；白皮书 7.2
│   ├── entropy/                    # MSEA 多源熵聚合 (白皮书 Section 5)：硬件噪声 + NIST SP 800-90B 强制验证 + Toeplitz 提取
│   │   ├── mod.rs
│   │   ├── aggregator.rs           # MSEA 核心：多源聚合 → 90B 测试 → Toeplitz 提取 Ri → ⊕ 合成 (scale-adaptive, H∞ ≥0.8 bits/byte；白皮书 1.1/5)
│   │   ├── sources.rs              # EntropySource trait 统一接口 (并行采集；白皮书 5)
│   │   ├── jitter.rs               # CPU jitter (TSC cycles, 1M samples；默认主源；白皮书 5)
│   │   ├── rdrand.rs               # Intel RdRand 后备 (可选 fallback；白皮书 5)
│   │   ├── audio.rs                # 麦克风热噪声 (10s 采集, locked-mode 强制；白皮书 5)
│   │   ├── video.rs                # 摄像头噪声 (10s 采集, locked-mode 强制；白皮书 5)
│   │   ├── custom.rs               # 用户自定义 EntropySource 模板 (trait 扩展；白皮书 5)
│   │   └── sp800_90b.rs            # NIST SP 800-90B 完整 10 项测试 (monobit/frequency/runs/FFT/MCV/Collision/Markov 等 estimators；H∞ <0.8 则 abort & burn；白皮书 1.1/5)
│   ├── net/                        # 网络协议：匿名网络 + 规模自适应 drand + 防重放
│   │   ├── mod.rs
│   │   ├── anonymous_net.rs        # 抽象 trait：Tor/I2P 统一 (create_destination/connect/send/recv；白皮书 1.2)
│   │   ├── tor/
│   │   │   ├── mod.rs
│   │   │   └── arti_impl.rs        # Tor 实现 (arti-client 封装, batched traffic；白皮书 1.2/3)
│   │   ├── i2p/
│   │   │   ├── mod.rs
│   │   │   └── i2pd_impl.rs        # I2P 实现 (i2pd-client 封装, 100% Tor 接口兼容；白皮书 1.2/3/9)
│   │   ├── drand/                  # 15min 公共随机流 (feature="drand", n≤50 启用；≈12.8 KiB/间隔；白皮书 1.1/2/5)
│   │   │   ├── mod.rs
│   │   │   ├── client.rs           # Drand 客户端 (runtime 每 15min；白皮书 2)
│   │   │   ├── stream.rs           # 流管理 (严格计时 + 32MB 缓存 + ed25519 验证 + 进度回调；白皮书 1.1/5)
│   │   │   ├── verify.rs           # ed25519 链上验证 (防篡改；白皮书 5)
│   │   │   └── health.rs           # Drand 健康检查 (compromise 检测 → MSEA fallback；白皮书 3)
│   │   ├── rendezvous.rs           # 双向引荐服务 (Tor/I2P destination 支持, batched out-of-order；白皮书 1.2/9)
│   │   ├── noise_xx.rs             # 手写 Noise_XX (fork snow, 无 rand → MSEA 派生；30s 握手；白皮书 4/6 Alg1)
│   │   ├── pairwise.rs             # Ki,j 1GB OTP pad 管理 (单向消耗, dual Tor/I2P；白皮书 1.2)
│   │   ├── sequencer.rs            # 96bit 随机序号 (MSEA 派生 ⊕ OTP block, 无 PRNG；防重放；白皮书 1.2/3)
│   │   ├── outbox.rs               # 加密离线队列 (7天指数退避 + presence/receipt/DBAP 联动；白皮书 1.2/6/7.1)
│   │   └── bandwidth.rs            # 流量限速 (≤2MB/h 防指纹；白皮书 1.2/6 Alg1)
│   ├── mpc/                        # BGW MPC 完整实现 (GF(2^8) 加法分享, t=⌈2n/3⌉；白皮书 1.1/6)
│   │   ├── mod.rs
│   │   ├── share.rs                # 阈值分享 (additive packing + SIP tags；白皮书 1.1/6)
│   │   ├── reconstruct.rs          # 重构 (Lagrange 插值, O(t^2) SIMD-accelerated；≤t-1 噪声；白皮书 1.1/7.1)
│   │   ├── aggregate.rs            # 聚合 (XOR 线性 + quorum O(n log n) 并行；n>50；白皮书 1.1/5/6)
│   │   └── quorum.rs               # 规模分区 (n>50 并行 MPC；白皮书 6)
│   ├── pad/                        # Master Pad 生命周期管理 (gigabyte-scale, offline-capable；白皮书 1.1/2/7.1)
│   │   ├── mod.rs
│   │   ├── lifecycle.rs            # Pad 生命周期 (usage_stats + 安全 prune/recycle；白皮书 2/3/7.1)
│   │   ├── monitor.rs              # Pad 锁定监控 (watchdog 集成；白皮书 6/8)
│   │   ├── burn.rs                 # 不可逆 zeroize (memguard, Iron Law 1/2/4/6 触发；白皮书 1.3/8)
│   │   ├── share_encrypt.rs        # 分享加密 (Scrypt(brain-passphrase)；白皮书 1.2)
│   │   └── usage_stats.rs          # 用量跟踪 (总 plaintext ≤ pad size；白皮书 3)
│   ├── protocol/                   # 协议层：异步 bootstrap + 状态机 + Iron Laws 执行
│   │   ├── mod.rs
│   │   ├── state_machine.rs        # 完整状态机 (CONSENSUS_PENDING for DBAP；白皮书 8)
│   │   ├── bootstrap/
│   │   │   ├── mod.rs
│   │   │   ├── orchestrator.rs     # 主调度 (异步 n-t 启动, 3-8min；rollback/timeout；白皮书 6/摘要)
│   │   │   ├── stages.rs           # 12 stage enum (每个 stage rollback + 超时 + 审计注释；白皮书 6)
│   │   │   ├── local.rs            # 面对面 20s 加群 (30s Noise XX；白皮书 7.2)
│   │   │   └── member_extend.rs    # 加新成员 30s (ratchet re-bootstrap + H_i 阈值分享；白皮书 3/7.2)
│   │   ├── control/
│   │   │   ├── mod.rs
│   │   │   ├── gap.rs              # 网络分裂检测 (DBAP burn 触发；白皮书 4)
│   │   │   ├── receipt.rs          # 收据联动 (outbox 集成；白皮书 6)
│   │   │   ├── presence.rs         # 在线/离线链接 (48h absence → burn；白皮书 6/8)
│   │   │   ├── retract.rs          # 撤回/驱逐 (3 co-signs, BGW 扩展；Iron Law 3；白皮书 1.3/8)
│   │   │   └── binary_attestation.rs  # DBAP 核心：local/pairwise/threshold 三层 (BLAKE3-HMAC + SIP + t 共识；分裂网 burn；白皮书 1.2/3/4/9)
│   │   ├── multi_device/           # 多设备支持 (白皮书 7.2)
│   │   │   ├── mod.rs
│   │   │   ├── linking.rs          # QR 临时链接 + 只读历史导出 (ratchet 安全；白皮书 7.2)
│   │   │   ├── roster.rs           # 设备指纹簿 (fingerprinting；白皮书 7.2)
│   │   │   └── limiter.rs          # 按安全等级限制数量 + 阈值签名 (threshold_sign.rs 集成；白皮书 7.2)
│   │   ├── group_permissions/      # 群组权限 (白皮书 7.2)
│   │   │   ├── mod.rs
│   │   │   ├── permissions.rs      # 权限检查核心 (role-based；白皮书 7.2)
│   │   │   ├── role_management.rs  # 角色变更 (需 t 阈值签名；白皮书 7.2)
│   │   │   └── threshold_sign.rs   # BGW 阈值签名扩展 (Iron Law 3/5；白皮书 1.3/7.2/8)
│   │   └── messaging.rs            # 消息协议入口 (queue + cleanup；白皮书 7/8)
│   ├── storage/                    # 持久化 (crash-safe；白皮书 1.2/9)
│   │   ├── mod.rs
│   │   ├── sqlite_scrypt.rs        # Scrypt 加密 DB (fingerprint_book for DBAP；白皮书 1.2)
│   │   └── raw_files.rs            # 原始文件存储 (shares Scrypt-encrypted；白皮书 9)
│   ├── contacts.rs                 # 本地联系人 + 角色存储 (roster 集成；白皮书 7.2)
│   ├── iron_laws.rs                # Iron Laws trait + 模式实现 (paranoid/moderate/practical；强制无计算密码；白皮书 1.3/2/8)
│   ├── history/                    # 历史管理 (白皮书 7.1/7.2)
│   │   ├── mod.rs
│   │   ├── api.rs                  # list/get/search (元数据索引；白皮书 7.1)
│   │   ├── index.rs                # 元数据倒排索引 (安全 prune；白皮书 7.1)
│   │   └── prune.rs                # 安全裁剪 + pad block 回收 (≤ pad size 跟踪；白皮书 3/7.1)
│   ├── messaging/                  # 消息队列 + 文件传输 (offline-capable；白皮书 7.1/8)
│   │   ├── mod.rs
│   │   ├── queue.rs                # 消息队列 (exponential backoff + Sixth Law 扫描；白皮书 1.3/7.1/8)
│   │   ├── delete.rs               # 删除/清理 (Sixth Law scanner for computational ciphers；白皮书 8/9)
│   │   ├── retract.rs              # 消息撤回 (Iron Law 集成；白皮书 8)
│   │   ├── cleanup.rs              # 清理扫描 (double confirmation before burn；白皮书 8)
│   │   └── file_transfer/
│   │       ├── mod.rs
│   │       ├── chunker.rs          # 文件分块 (4096B OTP chunks；白皮书 7.1)
│   │       ├── sender.rs           # 发送器 (batched over OTP；白皮书 7.1)
│   │       └── receiver.rs         # 接收器 (reconstruct on-demand；白皮书 7.1)
│   ├── group_history/              # 群组历史 (白皮书 7.2)
│   │   ├── mod.rs
│   │   ├── share.rs                # 历史分享 (阈值安全；白皮书 7.2)
│   │   ├── verify.rs               # 验证 (SIP + DBAP；白皮书 7.2)
│   │   └── policy.rs               # 策略 (prune/recycle；白皮书 7.1)
│   ├── audit.rs                    # 本地审计日志 (DBAP 事件/共识/污染警报；白皮书 8/9)
│   ├── recovery/                   # 恢复/继承 (白皮书 1.3/8)
│   │   ├── mod.rs
│   │   ├── export.rs               # 导出 (pre-shared offline keys；Iron Law 4；白皮书 8)
│   │   ├── import.rs               # 导入 (30 days offline + 3 signatures；DBAP-verified；白皮书 1.3/8)
│   │   ├── verify.rs               # 验证 (阈值共识；白皮书 8)
│   │   └── local_transfer.rs       # 本地传输 (QR/面对面；白皮书 7.2)
│   ├── binary_verify/              # DBAP 本地层 (白皮书 1.2/9)
│   │   ├── mod.rs
│   │   ├── local_self_verify.rs    # 分段 BLAKE3-HMAC (Scrypt 密钥 + 本地熵；运行时自验证；白皮书 1.2)
│   │   └── genesis_hash.rs         # Build-time 生成 (binary fingerprint；白皮书 1.2)
│   ├── watchdog.rs                 # 看门狗监控 (pad/DBAP/Tor/entropy/locked-mode；异常 → burn；Iron Law 1/8；白皮书 摘要/6/8)
│   └── platform/
│       ├── mod.rs
│       └── pc.rs                   # PC 平台实现：locked-mode (禁用 USB/Bluetooth) + memguard + process_freeze + capability_check (AVX512/mlock/权限/环境 fingerprint；白皮书 5/6/9)
├── include/                        # C 兼容头 (cbindgen 生成；FFI 支持)
│   └── togm.h
├── docs/                           # 完整文档 (白皮书合规)
│   ├── WHITEPAPER_COMPLIANCE.md    # 白皮书严格遵守 (ITS 纯度 + 强制要求；白皮书 9)
│   ├── DBAP.md                     # DBAP 详解 (三层 + 分裂网；白皮书 1.2/4)
│   ├── I2P_SUPPORT.md              # I2P 集成指南 (兼容 Tor；白皮书 9)
│   └── RUST_AUDIT_FIXES.md         # Rust 审计修复 (v3.3 RIE 变更 + Trail of Bits/Cure53 邀请；白皮书 10)
├── tests/                          # 覆盖率 >98% (单元 + 集成；白皮书 9)
│   ├── integration/
│   │   ├── dbap_full_cycle.rs      # DBAP 三层完整测试 (分裂网 burn + 共识；白皮书 1.2/9)
│   │   ├── bootstrap_all_stages.rs # Bootstrap 全阶段 (rollback/timeout/MSEA；白皮书 6)
│   │   └── member_extend.rs        # 成员扩展 (ratchet re-bootstrap；白皮书 7.2)
│   └── unit/                       # 所有模块单元测试 (core/entropy/net/mpc 等；>98% coverage)
└── examples/                       # 多语言 FFI 示例 (Swift/C++/Python；绑定 lib.rs API)
    ├── swift/
    ├── cpp/
    └── python/