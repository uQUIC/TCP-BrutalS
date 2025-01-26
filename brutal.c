#include <linux/module.h>
#include <linux/version.h>
#include <linux/random.h> // 导入随机数生成头文件
#include <linux/delay.h>  // 导入延时头文件
#include <net/tcp.h>
#include <linux/math64.h>

#if IS_ENABLED(CONFIG_IPV6) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <net/transp_v6.h>
#else
#warning IPv6 support is disabled. BrutalS will only work with IPv4. \
 Please ensure you have enabled CONFIG_IPV6 in your kernel config \
 and your kernel version is greater than 5.8.
#endif

#define INIT_PACING_RATE 125000 // 1 Mbps
#define INIT_CWND_GAIN 20

#define MIN_PACING_RATE 62500 // 500 Kbps
#define MIN_CWND_GAIN 5
#define MAX_CWND_GAIN 80
#define MIN_CWND 4

#ifndef ICSK_CA_PRIV_SIZE
#error "ICSK_CA_PRIV_SIZE not defined"
#else
// This is the size of the private data area in struct inet_connection_sock
// The size varies between Linux versions
// We use it to calculate the number of slots in the packet info array
#define RAW_PKT_INFO_SLOTS ((ICSK_CA_PRIV_SIZE - 2 * sizeof(u64)) / sizeof(struct brutal_pkt_info))
#define PKT_INFO_SLOTS (RAW_PKT_INFO_SLOTS < 3 ? 3 : (RAW_PKT_INFO_SLOTS > 5 ? 5 : RAW_PKT_INFO_SLOTS))
#endif

#define MIN_PKT_INFO_SAMPLES 50
#define MIN_ACK_RATE_PERCENT 80

#define TCP_BRUTAL_PARAMS 23301

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static u64 tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return div_u64(tp->tcp_mstamp, USEC_PER_SEC);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
// see https://github.com/torvalds/linux/commit/9a568de4818dea9a05af141046bd3e589245ab83
static u64 tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return div_u64(tp->tcp_mstamp.stamp_us, USEC_PER_SEC);
}
#else
#include <linux/jiffies.h>
static u64 tcp_sock_get_sec(const struct tcp_sock *tp)
{
    return div_u64(jiffies_to_usecs(tcp_time_stamp), USEC_PER_SEC);
}
#endif

struct brutal_pkt_info
{
    u64 sec;
    u32 acked;
    u32 losses;
};

struct brutal
{
    u64 rate;
    u32 cwnd_gain;

    struct brutal_pkt_info slots[PKT_INFO_SLOTS];
};

struct brutal_params
{
    u64 rate;      // Send rate in bytes per second
    u32 cwnd_gain; // CWND gain in tenths (10=1.0)
} __packed;

static struct proto tcp_prot_override __ro_after_init;
#ifdef _TRANSP_V6_H
static struct proto tcpv6_prot_override __ro_after_init;
#endif // _TRANSP_V6_H

#ifdef _LINUX_SOCKPTR_H
static int brutal_set_params(struct sock *sk, sockptr_t optval, unsigned int optlen)
#else
static int brutal_set_params(struct sock *sk, char __user *optval, unsigned int optlen)
#endif
{
    struct brutal *brutal = inet_csk_ca(sk);
    struct brutal_params params;

    if (optlen < sizeof(params))
        return -EINVAL;

#ifdef _LINUX_SOCKPTR_H
    if (copy_from_sockptr(&params, optval, sizeof(params)))
        return -EFAULT;
#else
    if (copy_from_user(&params, optval, sizeof(params)))
        return -EFAULT;
#endif

    // Sanity checks
    if (params.rate < MIN_PACING_RATE)
        return -EINVAL;
    if (params.cwnd_gain < MIN_CWND_GAIN || params.cwnd_gain > MAX_CWND_GAIN)
        return -EINVAL;

    brutal->rate = params.rate;
    brutal->cwnd_gain = params.cwnd_gain;

    return 0;
}

#ifdef _LINUX_SOCKPTR_H
static int brutal_tcp_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
#else
static int brutal_tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen)
#endif
{
    if (level == IPPROTO_TCP && optname == TCP_BRUTAL_PARAMS)
        return brutal_set_params(sk, optval, optlen);
    else
        return tcp_prot.setsockopt(sk, level, optname, optval, optlen);
}

#ifdef _TRANSP_V6_H
#ifdef _LINUX_SOCKPTR_H
static int brutal_tcpv6_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval, unsigned int optlen)
#else  // _LINUX_SOCKPTR_H
static int brutal_tcpv6_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen)
#endif // _LINUX_SOCKPTR_H
{
    if (level == IPPROTO_TCP && optname == TCP_BRUTAL_PARAMS)
        return brutal_set_params(sk, optval, optlen);
    else
        return tcpv6_prot.setsockopt(sk, level, optname, optval, optlen);
}
#endif // _TRANSP_V6_H

static void brutal_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct brutal *brutal = inet_csk_ca(sk);

    if (sk->sk_family == AF_INET)
        sk->sk_prot = &tcp_prot_override;
#ifdef _TRANSP_V6_H
    else if (sk->sk_family == AF_INET6)
        sk->sk_prot = &tcpv6_prot_override;
#endif // _TRANSP_V6_H
    else
        BUG(); // WTF?

    tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

    brutal->rate = INIT_PACING_RATE;
    brutal->cwnd_gain = INIT_CWND_GAIN;

    memset(brutal->slots, 0, sizeof(brutal->slots));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    // Pacing is REQUIRED for Brutal to work, but Linux only has internal pacing after 4.13.
    // For kernels prior to 4.13, you MUST add fq pacing manually (e.g. "tc qdisc add dev eth0 root fq pacing")
    // or rate control will be broken.
    // See https://github.com/torvalds/linux/commit/218af599fa635b107cfe10acf3249c4dfe5e4123 for details.
    cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
#endif
}

// Copied from tcp.h for compatibility reasons
static inline u32 brutal_tcp_snd_cwnd(const struct tcp_sock *tp)
{
    return tp->snd_cwnd;
}

// Copied from tcp.h for compatibility reasons
static inline void brutal_tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
    WARN_ON_ONCE((int)val <= 0);
    tp->snd_cwnd = val;
}

/*
 * TCP-BrutalS - TCP Congestion Control
 * Version: v0.1.3
 * Last Update: 2025-01-26 06:49:10 UTC
 * Author: v2eth
 * Maintainer: X2ET
 */

// 定义网络质量等级
#define NETWORK_QUALITY_EXCELLENT 90
#define NETWORK_QUALITY_GOOD     80
#define NETWORK_QUALITY_FAIR     70
#define NETWORK_QUALITY_POOR     60

// 定义RTT阈值（微秒）
#define RTT_THRESHOLD_LOW    50000   // 50ms
#define RTT_THRESHOLD_HIGH   200000  // 200ms

// 反检测相关定义
#define PATTERN_HISTORY_SIZE 16
#define NOISE_MIN           97    // 最小噪声系数
#define NOISE_MAX          103    // 最大噪声系数
#define PATTERN_THRESHOLD    5    // 模式检测阈值
#define TIME_VARIATION_MAX  50    // 最大时间变异(ms)

// 性能优化相关定义
#define PERF_CACHE_SIZE     64    // 性能缓存大小
#define RTT_HISTORY_SIZE    32    // RTT历史大小
#define RATE_HISTORY_SIZE   32    // 速率历史大小
#define PERF_UPDATE_INTERVAL 1000 // 性能更新间隔(ms)

enum transmission_mode {
    BURST_MODE,         // 高速突发模式
    STABLE_MODE,        // 平稳传输模式
    SLOW_GROWTH_MODE,   // 缓慢增长模式
    JITTER_MODE,        // 抖动模式
    MODE_COUNT          // 模式计数，用于随机选择模式
};

// 自适应控制结构
struct adaptive_control {
    u32 network_quality;    // 网络质量评分 (0-100)
    u32 last_rtt;          // 上次的RTT
    u32 rtt_min;           // 最小RTT
    u32 rtt_max;           // 最大RTT
    u32 loss_count;        // 连续丢包计数
    u32 ack_count;         // 连续确认计数
    u32 quality_samples;   // 样本数量
};

// 反检测控制结构
struct anti_detection {
    u64 rate_history[PATTERN_HISTORY_SIZE];  // 速率历史
    u32 rate_index;                          // 当前速率索引
    u32 pattern_count;                       // 模式重复计数
    u32 last_adjustment_time;                // 上次调整时间
    u32 entropy_pool[4];                     // 熵池
    bool pattern_detected;                    // 模式检测标志
};

// 性能优化结构
struct performance_metrics {
    u64 rate_history[RATE_HISTORY_SIZE];     // 速率历史
    u32 rtt_history[RTT_HISTORY_SIZE];       // RTT历史
    u32 rate_index;                          // 速率历史索引
    u32 rtt_index;                           // RTT历史索引
    u64 total_rate;                          // 总速率
    u32 total_rtt;                           // 总RTT
    u32 sample_count;                        // 样本数
    u32 last_update;                         // 上次更新时间
};

// 定义当前的传输模式及控制变量
static enum transmission_mode current_mode = STABLE_MODE;
static u32 mode_duration_counter = 0;
static u32 last_fluctuation_factor = 100;
static u32 fluctuation_min = 95;
static u32 fluctuation_max = 100;

// 初始化控制结构
static struct adaptive_control ac = {
    .network_quality = 80,
    .last_rtt = 0,
    .rtt_min = U32_MAX,
    .rtt_max = 0,
    .loss_count = 0,
    .ack_count = 0,
    .quality_samples = 0,
};

static struct anti_detection ad = {
    .rate_index = 0,
    .pattern_count = 0,
    .last_adjustment_time = 0,
    .pattern_detected = false,
};

static struct performance_metrics perf = {
    .rate_index = 0,
    .rtt_index = 0,
    .total_rate = 0,
    .total_rtt = 0,
    .sample_count = 0,
    .last_update = 0,
};

// 性能优化：速率计算缓存
static inline u64 get_cached_rate(u64 rate) {
    u32 index = perf.rate_index % RATE_HISTORY_SIZE;
    perf.rate_history[index] = rate;
    perf.total_rate += rate;
    perf.rate_index++;
    
    if (perf.rate_index >= RATE_HISTORY_SIZE) {
        perf.total_rate = 0;
        for (int i = 0; i < RATE_HISTORY_SIZE; i++) {
            perf.total_rate += perf.rate_history[i];
        }
        perf.rate_index = 0;
    }
    
    return perf.total_rate / min(perf.rate_index, RATE_HISTORY_SIZE);
}

// 性能优化：RTT计算缓存
static inline u32 get_cached_rtt(u32 rtt) {
    u32 index = perf.rtt_index % RTT_HISTORY_SIZE;
    perf.rtt_history[index] = rtt;
    perf.total_rtt += rtt;
    perf.rtt_index++;
    
    if (perf.rtt_index >= RTT_HISTORY_SIZE) {
        perf.total_rtt = 0;
        for (int i = 0; i < RTT_HISTORY_SIZE; i++) {
            perf.total_rtt += perf.rtt_history[i];
        }
        perf.rtt_index = 0;
    }
    
    return perf.total_rtt / min(perf.rtt_index, RTT_HISTORY_SIZE);
}

// 更新熵池
static void update_entropy_pool(struct anti_detection *ad) {
    u32 time = (u32)ktime_get_real_seconds();
    u32 jiffies_val = jiffies;
    
    ad->entropy_pool[0] ^= time;
    ad->entropy_pool[1] ^= jiffies_val;
    ad->entropy_pool[2] ^= (time << 16) | (time >> 16);
    ad->entropy_pool[3] ^= (jiffies_val << 16) | (jiffies_val >> 16);
}

// 生成随机噪声
static u32 generate_noise(struct anti_detection *ad) {
    update_entropy_pool(ad);
    u32 random_val = ad->entropy_pool[0] ^ ad->entropy_pool[1] ^ 
                    ad->entropy_pool[2] ^ ad->entropy_pool[3];
    return NOISE_MIN + (random_val % (NOISE_MAX - NOISE_MIN + 1));
}

// 检测模式
static bool detect_pattern(struct anti_detection *ad, u64 current_rate) {
    int i, count = 0;
    ad->rate_history[ad->rate_index] = current_rate;
    ad->rate_index = (ad->rate_index + 1) % PATTERN_HISTORY_SIZE;

    // 检查连续相似的速率
    for (i = 1; i < PATTERN_HISTORY_SIZE; i++) {
        u64 prev = ad->rate_history[i-1];
        u64 curr = ad->rate_history[i];
        if (prev && curr && abs(prev - curr) < (prev / 20))
            count++;
    }

    return count >= PATTERN_THRESHOLD;
}

// 应用反检测措施
static u64 apply_anti_detection(u64 rate, struct anti_detection *ad) {
    u32 noise;
    u32 current_time = jiffies_to_msecs(jiffies);
    
    if (detect_pattern(ad, rate)) {
        ad->pattern_count++;
        ad->pattern_detected = true;
    } else {
        ad->pattern_count = 0;
        ad->pattern_detected = false;
    }

    // 根据检测结果应用不同程度的随机化
    if (ad->pattern_detected) {
        noise = generate_noise(ad);
        rate = div_u64(rate * noise, 100);
        
        if (current_time - ad->last_adjustment_time > TIME_VARIATION_MAX) {
            u32 delay = generate_noise(ad) % TIME_VARIATION_MAX;
            msleep(delay);
            ad->last_adjustment_time = current_time;
        }
    } else {
        noise = NOISE_MIN + (generate_noise(ad) % ((NOISE_MAX - NOISE_MIN) / 2));
        rate = div_u64(rate * noise, 100);
    }

    return rate;
}

// 更新网络质量评分
static void update_network_quality(struct adaptive_control *ac, 
                                 u32 rtt_us, u32 acked, u32 losses) {
    // 应用性能优化的RTT计算
    u32 cached_rtt = get_cached_rtt(rtt_us);
    
    ac->last_rtt = cached_rtt;
    ac->rtt_min = min(ac->rtt_min, cached_rtt);
    ac->rtt_max = max(ac->rtt_max, cached_rtt);

    u32 rtt_score;
    if (cached_rtt <= RTT_THRESHOLD_LOW)
        rtt_score = 40;
    else if (cached_rtt >= RTT_THRESHOLD_HIGH)
        rtt_score = 10;
    else
        rtt_score = 40 - ((cached_rtt - RTT_THRESHOLD_LOW) * 30) / 
                        (RTT_THRESHOLD_HIGH - RTT_THRESHOLD_LOW);

    u32 loss_score;
    if (acked + losses == 0)
        loss_score = 40;
    else
        loss_score = 40 * acked / (acked + losses);

    u32 stability_score;
    u32 rtt_variance = ac->rtt_max - ac->rtt_min;
    if (rtt_variance < RTT_THRESHOLD_LOW)
        stability_score = 20;
    else if (rtt_variance >= RTT_THRESHOLD_HIGH)
        stability_score = 5;
    else
        stability_score = 20 - ((rtt_variance - RTT_THRESHOLD_LOW) * 15) /
                              (RTT_THRESHOLD_HIGH - RTT_THRESHOLD_LOW);

    ac->network_quality = rtt_score + loss_score + stability_score;
    ac->quality_samples++;
}

// 计算基础速率 f(x)
static u64 calculate_base_rate(struct brutal *brutal, u32 acked, u32 losses)
{
    u32 ack_rate;
    u64 base_rate = brutal->rate;

    if (acked + losses < MIN_PKT_INFO_SAMPLES)
        ack_rate = 100;
    else {
        ack_rate = acked * 100 / (acked + losses);
        if (ack_rate < MIN_ACK_RATE_PERCENT)
            ack_rate = MIN_ACK_RATE_PERCENT;
    }

    base_rate *= 100;
    return div_u64(base_rate, ack_rate);
}

// 基于网络质量自适应调整波动范围
static void adapt_fluctuation_range(struct adaptive_control *ac) {
    if (ac->network_quality >= NETWORK_QUALITY_EXCELLENT) {
        fluctuation_min = 98;
        fluctuation_max = 100;
    } else if (ac->network_quality >= NETWORK_QUALITY_GOOD) {
        fluctuation_min = 95;
        fluctuation_max = 100;
    } else if (ac->network_quality >= NETWORK_QUALITY_FAIR) {
        fluctuation_min = 85;
        fluctuation_max = 95;
    } else {
        fluctuation_min = 80;
        fluctuation_max = 90;
    }
}

// 应用模式调制，实现g(f(x))
static u64 apply_mode_modulation(u64 base_rate, struct adaptive_control *ac)
{
    if (++mode_duration_counter >= 100) {
        if (ac->network_quality >= NETWORK_QUALITY_EXCELLENT)
            current_mode = BURST_MODE;
        else if (ac->network_quality >= NETWORK_QUALITY_GOOD)
            current_mode = STABLE_MODE;
        else if (ac->network_quality >= NETWORK_QUALITY_FAIR)
            current_mode = SLOW_GROWTH_MODE;
        else
            current_mode = JITTER_MODE;

        mode_duration_counter = 0;
        last_fluctuation_factor = 100;
    }

    u32 time_seed = (u32)ktime_get_seconds() ^ (mode_duration_counter << 16);
    adapt_fluctuation_range(ac);

    switch (current_mode) {
        case BURST_MODE:
            fluctuation_min = max(fluctuation_min, 98);
            break;
            
        case STABLE_MODE:
            fluctuation_min = max(fluctuation_min, 95);
            break;
            
        case SLOW_GROWTH_MODE:
            base_rate = div_u64(base_rate * 
                (fluctuation_min + mode_duration_counter % 10), 100);
            break;
            
        case JITTER_MODE:
            if ((time_seed & 0xF) < 3) {
                u32 jitter = 1 + (time_seed % 3);
                msleep(jitter);
            }
            break;
    }

    u32 update_threshold = 3 + (time_seed % 5);
    if (mode_duration_counter % update_threshold == 0) {
        u32 range = fluctuation_max - fluctuation_min + 1;
        last_fluctuation_factor = fluctuation_min + (time_seed % range);
    }

    // 应用反检测措施并进行性能优化
    base_rate = apply_anti_detection(base_rate, &ad);
    base_rate = get_cached_rate(base_rate);

    return div_u64(base_rate * last_fluctuation_factor, 100);
}

// 性能监控结构
struct performance_monitor {
    u64 last_update_time;      // 上次更新时间
    u32 updates_count;         // 更新计数
    u32 pattern_detections;    // 模式检测次数
    u32 mode_switches;         // 模式切换次数
    u32 quality_updates;       // 质量更新次数
};

static struct performance_monitor pmon = {
    .last_update_time = 0,
    .updates_count = 0,
    .pattern_detections = 0,
    .mode_switches = 0,
    .quality_updates = 0,
};

// 更新性能监控
static inline void update_performance_monitor(void) {
    u64 current_time = ktime_get_real_ns();
    pmon.updates_count++;
    
    if (current_time - pmon.last_update_time >= NSEC_PER_SEC) {
        pmon.last_update_time = current_time;
        pmon.updates_count = 0;
        pmon.pattern_detections = 0;
        pmon.mode_switches = 0;
        pmon.quality_updates = 0;
    }
}

// 更新速率主函数
static void brutal_update_rate(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct brutal *brutal = inet_csk_ca(sk);

    u64 sec = tcp_sock_get_sec(tp);
    u64 min_sec = sec - PKT_INFO_SLOTS;
    u32 acked = 0, losses = 0;
    u32 cwnd;

    u32 mss = tp->mss_cache;
    u32 rtt_ms = (tp->srtt_us >> 3) / USEC_PER_MSEC;
    if (!rtt_ms)
        rtt_ms = 1;

    for (int i = 0; i < PKT_INFO_SLOTS; i++) {
        if (brutal->slots[i].sec >= min_sec) {
            acked += brutal->slots[i].acked;
            losses += brutal->slots[i].losses;
        }
    }

    // 更新性能监控
    update_performance_monitor();
    pmon.quality_updates++;

    // 更新网络质量
    update_network_quality(&ac, tp->srtt_us, acked, losses);
    
    // 计算基础速率
    u64 base_rate = calculate_base_rate(brutal, acked, losses);
    
    // 应用模式调制
    u64 final_rate = apply_mode_modulation(base_rate, &ac);

    // 计算拥塞窗口
    cwnd = div_u64(final_rate, MSEC_PER_SEC);
    cwnd *= rtt_ms;
    cwnd /= mss;
    cwnd *= brutal->cwnd_gain;
    cwnd /= 10;
    cwnd = max_t(u32, cwnd, MIN_CWND);

    // 设置拥塞窗口和速率
    brutal_tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));
    WRITE_ONCE(sk->sk_pacing_rate, 
        min_t(u64, final_rate, READ_ONCE(sk->sk_max_pacing_rate)));
}

// TCP-BrutalS 拥塞控制算法初始化
static void brutal_init(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct brutal *brutal = inet_csk_ca(sk);

    brutal->rate = tp->snd_cwnd * tp->mss_cache * USEC_PER_SEC;
    brutal->rate = div_u64(brutal->rate, (u64)tp->srtt_us);
    brutal->cwnd_gain = 10;    // 默认增益为1.0

    // 初始化性能监控
    pmon.last_update_time = ktime_get_real_ns();
    pmon.updates_count = 0;
    pmon.pattern_detections = 0;
    pmon.mode_switches = 0;
    pmon.quality_updates = 0;

    // 初始化性能度量缓存
    memset(&perf, 0, sizeof(struct performance_metrics));
    perf.last_update = jiffies;
}

// TCP-BrutalS 拥塞控制算法释放
static void brutal_release(struct sock *sk)
{
    // 清理性能监控数据
    memset(&pmon, 0, sizeof(struct performance_monitor));
    
    // 清理性能度量缓存
    memset(&perf, 0, sizeof(struct performance_metrics));
}

// TCP-BrutalS 拥塞控制算法结构
struct tcp_congestion_ops tcp_brutal_ops = {
    .flags = TCP_CONG_NON_RESTRICTED,
    .name = "brutal",
    .owner = THIS_MODULE,
    .init = brutal_init,
    .release = brutal_release,
    .cong_control = brutal_update_rate,
    .ssthresh = tcp_reno_ssthresh,
    .undo_cwnd = tcp_reno_undo_cwnd,
};

// 模块初始化
static int __init brutal_register(void)
{
    BUILD_BUG_ON(sizeof(struct brutal) > ICSK_CA_PRIV_SIZE);
    return tcp_register_congestion_control(&tcp_brutal_ops);
}

// 模块清理
static void __exit brutal_unregister(void)
{
    tcp_unregister_congestion_control(&tcp_brutal_ops);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
static void brutal_main(struct sock *sk, u32 ack, int flag, const struct rate_sample *rs)
#else
static void brutal_main(struct sock *sk, const struct rate_sample *rs)
#endif
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct brutal *brutal = inet_csk_ca(sk);

    u64 sec;
    u32 slot;

    // Ignore invalid rate samples
    if (rs->delivered < 0 || rs->interval_us <= 0)
        return;

    sec = tcp_sock_get_sec(tp);
    div_u64_rem(sec, PKT_INFO_SLOTS, &slot);

    if (brutal->slots[slot].sec == sec)
    {
        // Current slot, update
        brutal->slots[slot].acked += rs->acked_sacked;
        brutal->slots[slot].losses += rs->losses;
    }
    else
    {
        // Uninitialized slot or slot expired
        brutal->slots[slot].sec = sec;
        brutal->slots[slot].acked = rs->acked_sacked;
        brutal->slots[slot].losses = rs->losses;
    }

    brutal_update_rate(sk);
}

static u32 brutal_undo_cwnd(struct sock *sk)
{
    return brutal_tcp_snd_cwnd(tcp_sk(sk));
}

static u32 brutal_ssthresh(struct sock *sk)
{
    return tcp_sk(sk)->snd_ssthresh;
}

static struct tcp_congestion_ops tcp_brutal_ops = {
    .flags = TCP_CONG_NON_RESTRICTED,
    .name = "brutal",
    .owner = THIS_MODULE,
    .init = brutal_init,
    .cong_control = brutal_main,
    .undo_cwnd = brutal_undo_cwnd,
    .ssthresh = brutal_ssthresh,
};

static int __init brutal_register(void)
{
    BUILD_BUG_ON(sizeof(struct brutal) > ICSK_CA_PRIV_SIZE);
    BUILD_BUG_ON(PKT_INFO_SLOTS < 1);

    tcp_prot_override = tcp_prot;
    tcp_prot_override.setsockopt = brutal_tcp_setsockopt;

#ifdef _TRANSP_V6_H
    tcpv6_prot_override = tcpv6_prot;
    tcpv6_prot_override.setsockopt = brutal_tcpv6_setsockopt;
#endif // _TRANSP_V6_H

    return tcp_register_congestion_control(&tcp_brutal_ops);
}

static void __exit brutal_unregister(void)
{
    tcp_unregister_congestion_control(&tcp_brutal_ops);
}

module_init(brutal_register);
module_exit(brutal_unregister);

MODULE_AUTHOR("Project Ether");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP BrutalS");
MODULE_VERSION("0.1.4");
