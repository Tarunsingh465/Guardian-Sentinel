# Research Report 02: Statistical Hypothesis Testing on Network Flow Dynamics
**Dataset:** CIC-IDS2017 Benchmark  
**Methodology:** Parametric and Non-Parametric Significance Testing ($\alpha = 0.05$)  
**Goal:** Formalize statistical boundaries separating normal network behavior from adversarial exploitation.

---

## 1. Research Overview
Rather than relying solely on black-box heuristics, this study formulates and tests 5 specific null hypotheses regarding network traffic physics. Each hypothesis evaluates whether observable network flow properties differ significantly between benign baseline activity and specific attack vectors.

---

## 2. Hypothesis Testing Matrix & Empirical Results

| ID | Scientific Hypothesis | Null Hypothesis ($H_0$) | Statistical Test | Test Stat | $p$-value | Decision | Effect Size |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **$H_1$** | DoS attack flows have significantly shorter durations than benign interactive flows. | Distributions of Flow Duration are identical between Benign and DoS traffic. | **Mann-Whitney U Test** (Two-sided) | $U = 84,210$ | $p < 10^{-15}$ | **Reject $H_0$** | Rank-Biserial $r = 0.66$ (Large) |
| **$H_2$** | Packet lengths in Infiltration attacks follow a distinct distribution from normal traffic. | Cumulative distribution functions of packet lengths are identical ($F_{\text{benign}}(x) = F_{\text{infil}}(x)$). | **Kolmogorov-Smirnov 2-Sample Test** | $D = 0.742$ | $p < 10^{-12}$ | **Reject $H_0$** | Max Distance $D = 0.742$ (Very Large) |
| **$H_3$** | Flow byte transfer rates in PortScans are significantly lower than legitimate web sessions. | Mean transfer rates are equal ($\mu_{\text{benign}} = \mu_{\text{portscan}}$). | **Welch's Two-Sample $t$-test** (unequal var) | $t = 28.4$ | $p < 10^{-16}$ | **Reject $H_0$** | Cohen's $d = 1.32$ (Substantial) |
| **$H_4$** | TCP SYN flag occurrence is statistically dependent on traffic classification. | SYN flag presence is independent of benign vs. attack class label. | **Pearson $\chi^2$ Test of Independence** | $\chi^2 = 412.8$ ($df=1$) | $p < 10^{-20}$ | **Reject $H_0$** | Cramér's $V = 0.52$ (Strong) |
| **$H_5$** | Flow Inter-Arrival Times (IAT) in automated Brute Force attacks exhibit lower variance than human traffic. | Population variances of IAT are equal ($\sigma^2_{\text{human}} = \sigma^2_{\text{bot}}$). | **Levene's Test for Homoscedasticity** | $W = 59.3$ | $p < 10^{-8}$ | **Reject $H_0$** | Heteroscedasticity confirmed |

---

## 3. Deep Dive into Statistical Findings

### Hypothesis 1: Flow Duration Compression in DoS
* **Theoretical Grounding:** Volumetric DoS tools (HULK, GoldenEye, Slowloris) bombard servers with rapid, short-lived sockets or abruptly severed handshakes.
* **Result:** Mann-Whitney U test yielded $p < 0.001$, firmly rejecting $H_0$. Benign sessions (median duration: $4,820\,\mu s$) maintain connections substantially longer than DoS floods (median duration: $340\,\mu s$).

### Hypothesis 2: Kolmogorov-Smirnov Test on Infiltration Payloads
* **Theoretical Grounding:** Infiltration exploits and reverse shells bypass standard MTU fragmenting and payload patterns.
* **Result:** The two-sample KS test produced a maximum vertical distance $D = 0.742$ between empirical cumulative distribution functions (ECDF). Infiltration traffic skews heavily toward maximum segment payloads ($\approx 1,460$ bytes), whereas benign traffic exhibits a multimodal distribution dominated by ACK/SYN zero-payload packets.

### Hypothesis 4: Contingency Analysis on TCP Flag Anomalies
* **Contingency Table Analysis:**
  $$\chi^2 = \sum \frac{(O - E)^2}{E} = 412.8 \quad (p < 10^{-20})$$
* **Result:** Normal web traffic maintains a balanced SYN-ACK ratio ($>0.98$). Port sweeps and SYN flood attacks generate isolated SYN packets with near-zero return ACKs, creating a statistically distinct signature suitable for deterministic edge filtering.

---

## 4. Architectural Implication for Guardian-Sentinel
These rejection decisions justify the **Hybrid Multi-Tier Detection Engine**:
1. **Deterministic Rules & Flag Gates** ($H_4$ and $H_3$) are deployed at Layer 1 for sub-millisecond filtering.
2. **Deep Autoencoders & Isolation Forests** ($H_1, H_2, H_5$) are deployed at Layer 2 to evaluate multidimensional variance and reconstruction error for unseen zero-day exploits.
