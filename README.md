# complete step-by-step guide to install and configure Suricata IDS/IPS on Kali linux

Suricata can be installed from Kali’s repository in a few commands, then configured as an IDS (monitor only) or IPS (inline blocking) by editing `suricata.yaml`, setting up rules, and optionally using NFQUEUE/iptables.[^1_1][^1_2][^1_3]
Below is a concise, practical step‑by‑step guide tailored for Kali.

***

## 1. Prepare Kali and install Suricata

- Update and upgrade Kali packages.
`sudo apt update && sudo apt upgrade -y`[^1_2][^1_1]
- Install Suricata from the Kali repository.
`sudo apt install suricata -y`[^1_1][^1_2]
- Verify installation and locate files:
    - `suricata --version`
    - Config: `/etc/suricata/suricata.yaml`
    - Rules dir (usually): `/etc/suricata/rules`[^1_2][^1_1]

***

## 2. Basic configuration (suricata.yaml)

- Open the main config file:
`sudo nano /etc/suricata/suricata.yaml`[^1_4][^1_1]
- Set the correct capture interface under the `af-packet` (or `pcap`) section, for example change `eth0` to your actual interface (e.g. `eth0`, `wlan0`, `ens33`).[^1_1]
- Ensure the `default-rule-path` and `rule-files` list point to your rules, for example:

```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
```

so that Suricata loads both built‑in and custom rule files.[^1_4]

***

## 3. Get and enable rules

- Use the rules that ship with the package, or download a ruleset (Emerging Threats, etc.) into `/etc/suricata/rules`.[^1_4][^1_1]
- Create a **local** rule file if it does not exist:
`sudo touch /etc/suricata/rules/local.rules`[^1_4]
- Add a simple test rule in `local.rules`, for example to alert on HTTP traffic:

```bash
sudo nano /etc/suricata/rules/local.rules
```

Example rule (simplified):
`alert http any any -> any any (msg:"Local HTTP test"; sid:1000001; rev:1;)`[^1_4]
- Confirm `local.rules` is included in `suricata.yaml` as shown above and save the file.[^1_4]

***

## 4. Run Suricata in IDS mode (monitor only)

- For quick testing, run Suricata directly in foreground IDS mode:
`sudo suricata -c /etc/suricata/suricata.yaml -i eth0`
replacing `eth0` with your interface.[^1_1]
- Suricata will log alerts to `/var/log/suricata/fast.log` and other log files by default; these are referenced in the configuration.[^1_4]
- Generate traffic (e.g. browse the web) and then check alerts:
`sudo tail -f /var/log/suricata/fast.log`[^1_4]

***

## 5. Switch rules from IDS to IPS behavior

- In IPS mode, rules that should **block** traffic must use actions such as `drop` or `reject` instead of `alert`.[^1_5]
- Edit rules you want to enforce and change the action, for example:

```bash
sudo nano /etc/suricata/rules/local.rules
```

Change:
`alert http any any -> any any (msg:"Local HTTP test"; sid:1000001; rev:1;)`
to:
`drop http any any -> any any (msg:"Local HTTP test - drop"; sid:1000001; rev:2;)`[^1_5]
- After modifying rules or `suricata.yaml`, restart Suricata (or stop and re‑run the command if you are running it manually).[^1_4]

***

## 6. Configure IPS inline mode with NFQUEUE

To actually **block** packets, Suricata must sit inline with traffic. On a single Kali host, NFQUEUE via iptables is the common method.[^1_3][^1_5]

### 6.1 Enable NFQUEUE mode in Suricata

- Ensure the NFQUEUE `af-packet` or `nfqueue` section is enabled in `suricata.yaml` (depending on version), typically something like:

```yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

or use the `nfqueue` run mode as indicated in the documentation; Kali’s defaults generally support IPS with NFQUEUE.[^1_3]

*(Exact YAML structure varies slightly by version, but your goal is to use a mode that supports inline dropping.)*[^1_3]

### 6.2 Add iptables NFQUEUE rules

- Redirect traffic through NFQUEUE so Suricata can inspect and drop:

```bash
sudo iptables -I INPUT 1  -j NFQUEUE
sudo iptables -I OUTPUT 1 -j NFQUEUE
sudo iptables -I FORWARD 1 -j NFQUEUE
```

This sends host and forwarded traffic into queue 0 for Suricata.[^1_3]
- On servers where only specific traffic should be inspected (e.g. SSH), narrow the rules:

```bash
sudo iptables -I INPUT 1  -p tcp --dport 22  -j NFQUEUE
sudo iptables -I OUTPUT 1 -p tcp --sport 22 -j NFQUEUE
```

which is a typical example to protect SSH connections.[^1_5]

***

## 7. Run Suricata in IPS mode

There are two common inline approaches on Kali:

- **AF‑Packet inline** (simple host‑based IPS on an interface):

```bash
sudo suricata -c /etc/suricata/suricata.yaml --af-packet=eth0
```

which starts Suricata capturing inline on `eth0` as an IPS.[^1_1]
- **NFQUEUE mode** (in combination with iptables rules above):
    - Start Suricata with NFQUEUE support enabled (the Kali build is compiled with Netfilter support).[^1_3]
    - When rules are set to `drop` and packets match them, Suricata will drop packets from the queue instead of letting iptables accept them.[^1_5][^1_3]

You can test blocking by triggering a rule (for example, traffic that matches a `drop` rule) and confirming that the connection fails while an entry appears in Suricata’s logs.[^1_5]

***

## 8. Managing logs and validating configuration

- Check configuration syntax before running:
`sudo suricata -T -c /etc/suricata/suricata.yaml`
which tests the config and rules for errors.[^1_4]
- Main log locations on Kali:
    - `/var/log/suricata/fast.log` – concise alert log.
    - `/var/log/suricata/eve.json` – richer JSON event log.[^1_4]
- Monitor logs while generating traffic to verify that IDS or IPS actions are triggered as expected.[^1_5][^1_4]

***

## 9. Optional: service integration

- On systems where Suricata is installed via packages, a systemd service is usually available:
    - `sudo systemctl enable suricata`
    - `sudo systemctl start suricata`
so Suricata runs automatically on boot with your configuration.[^1_1]
- When using the service, ensure `suricata.yaml` runmode and interface settings are correct so it starts in IDS or IPS mode as desired.[^1_1]

If you share your exact Kali version and whether you want host‑based protection only or gateway‑style IPS for a whole network, a more tailored set of commands and example rules can be provided.
<span style="display:none">[^1_10][^1_6][^1_7][^1_8][^1_9]</span>

<div align="center">⁂</div>

[^1_1]: https://hackzone.in/blog/step-by-step-guide-how-to-install-and-configure-suricata-ids-on-kali-purple/

[^1_2]: https://dropvps.com/blog/using-kali-linux-to-test-and-configure-ids-on-your-vps/

[^1_3]: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Setting_up_IPSinline_for_Linux

[^1_4]: https://docs.suricata.io/en/latest/rule-management/adding-your-own-rules.html

[^1_5]: https://www.digitalocean.com/community/tutorials/how-to-configure-suricata-as-an-intrusion-prevention-system-ips-on-ubuntu-20-04

[^1_6]: https://wafatech.sa/blog/linux/linux-security/comprehensive-guide-to-setting-up-suricata-ids-ips-on-your-linux-server/

[^1_7]: https://www.criticaldesign.net/post/how-to-setup-a-suricata-ips

[^1_8]: https://www.youtube.com/watch?v=8Q3Nhyvh-1I

[^1_9]: https://www.hackingarticles.in/configure-suricata-ids-ubuntu/

[^1_10]: https://www.youtube.com/watch?v=aGCxsGfWgqc


---

# Prepare Kali Linux prerequisites and system requirements for Suricata

Kali Linux itself has modest requirements, but running Suricata comfortably (especially as IPS) benefits from more CPU, RAM, and a good NIC.  Below are practical prerequisites and system requirements before installing Suricata on Kali.[^2_1][^2_2]

***

## Hardware requirements

For a **single‑host / lab** deployment on Kali:

- CPU: At least 2 CPU cores; 4+ cores recommended if you plan to enable many rules, use IPS, or monitor heavy traffic.[^2_3][^2_2]
- RAM: Minimum 4 GB RAM; 8 GB or more recommended when running multiple security tools or heavy rulesets.[^2_2][^2_1]
- Disk: At least 20 GB free disk space for Kali plus logs; more if you keep long‑term Suricata logs (50–100 GB is comfortable).[^2_1][^2_2]

For **higher throughput** (hundreds of Mbps to multiple Gbps) you need:

- Many CPU cores (modern Xeon/Epyc class, 8–20+ cores) and large RAM (32–128 GB) to process packets and rules at line rate.[^2_4][^2_5]
- Server‑grade NICs (Intel i210/i350, 10G/25G NICs, etc.) and, ideally, dedicating a NIC to Suricata traffic capture.[^2_6][^2_5][^2_4]

***

## Network and interface prerequisites

- At least **one** network interface dedicated to the traffic you want to inspect (e.g. `eth0` or `wlan0`).[^2_6]
- For span/mirror or gateway‑style setups, having **two NICs** (one for management, one for monitored traffic) is strongly recommended.[^2_6]
- Promiscuous mode must be supported and enabled on the capture interface if you are sniffing mirrored or shared segments.[^2_3]

***

## Operating system and kernel prerequisites

- A fully updated Kali Linux install on 64‑bit hardware, meeting Kali’s standard “desktop” baseline (2 GB RAM and 20 GB disk minimum).[^2_1]
- Linux kernel 4.15 or newer is required for advanced features like eBPF/XDP offload (Kali’s current kernels satisfy this).[^2_7]
- Netfilter/iptables or nftables must be available and enabled if you intend to use Suricata in IPS mode with NFQUEUE.[^2_8][^2_3]

***

## Software packages and user privileges

Before installing Suricata, prepare:

- Root or sudo access to install packages and configure networking (iptables/nftables).[^2_2]
- Development and capture libraries are not strictly required when using the Kali package, but for advanced builds/tuning you may need:
    - `libpcap` for packet capture,
    - `libnetfilter-queue` for NFQUEUE IPS mode,
    - `clang/llvm` if using eBPF/XDP acceleration.[^2_7][^2_3]
- Sufficient disk I/O performance (SSD preferred) to handle Suricata log output (`eve.json`, `fast.log`, etc.) under load.[^2_3][^2_2]

***

## Performance and tuning considerations

- Throughput capacity depends mainly on ruleset size, CPU cores, and NIC quality; even modest hardware can handle small lab traffic, while multi‑Gbps monitoring needs many cores and tuned configs.[^2_5][^2_4]
- For better performance on Kali:
    - Use multi‑queue NICs and enable Suricata’s multi‑threading and AF‑Packet tuning,
    - Pin Suricata threads to specific cores and avoid running many heavy tools concurrently on the same machine.[^2_7][^2_3]

If you share your Kali host specs (CPU cores, RAM, NIC, expected traffic speed), a tailored sizing and tuning recommendation for Suricata can be given.
<span style="display:none">[^2_10][^2_11][^2_9]</span>

<div align="center">⁂</div>

[^2_1]: https://www.kali.org/docs/installation/hard-disk-install/

[^2_2]: https://serverspace.io/support/help/how-to-install-suricata-on-ubuntu-20-04/

[^2_3]: https://docs.suricata.io/en/latest/performance/high-performance-config.html

[^2_4]: https://forum.suricata.io/t/hardware-specification-for-suricata/2545

[^2_5]: https://suricon.net/wp-content/uploads/2019/11/SURICON2019_Pushing-Suricata-Towards-90-Gbit_s-and-More.pdf

[^2_6]: https://campus.barracuda.com/product/xdr/doc/359006701/installing-suricata-on-linux-for-the-xdr-collector/

[^2_7]: https://docs.suricata.io/en/suricata-8.0.0/capture-hardware/ebpf-xdp.html

[^2_8]: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Setting_up_IPSinline_for_Linux

[^2_9]: https://www.reddit.com/r/PFSENSE/comments/dh7nhu/what_hw_spec_required_to_run_suricata_ntopng/

[^2_10]: https://forum.opnsense.org/index.php?topic=16131.0

[^2_11]: https://forum.netgate.com/topic/144490/suircata-throughput


---

# Which NIC models work best for Suricata packet capture

For Suricata on Kali, Intel server‑grade NICs with good Linux drivers work best, especially the i210/i340/i350 families, followed by higher‑end cards from vendors like Chelsio and Mellanox.  The key is stable drivers, multiple queues, and support for disabling offloads cleanly.[^3_1][^3_2][^3_3]

***

## Recommended NIC families

- **Intel i210 / i211**
    - Widely recommended for IDS/IPS due to robust Linux support, multiple queues, and stable performance under load.[^3_4][^3_1]
    - Suitable for 1 Gbps links on mid‑range hardware and common in small servers and appliances.[^3_3]
- **Intel i340 / i350 (including I350‑T2/T4)**
    - Frequently cited as a “go‑to” Suricata NIC: inexpensive used, multi‑port, and reliable.[^3_2][^3_4]
    - Good choice for inline setups or multi‑interface firewalls, with solid driver support and SR‑IOV on i350 variants.[^3_2]
- **Chelsio (e.g., T4/T5 series)**
    - Designed for high‑performance networking, often used for multi‑Gbps IDS/IPS workloads.[^3_1]
    - Strong offload and multi‑queue support; useful if planning 10 Gbps+ monitoring.[^3_5][^3_6]
- **Mellanox ConnectX series**
    - Popular for high‑speed (10G/25G/40G) Linux deployments and work well with Suricata when configured correctly.[^3_5][^3_1]
    - Good driver quality and support for advanced features like XDP/eBPF in newer kernels.[^3_6]

***

## What to avoid or be cautious with

- Very old Intel PRO/1000 and low‑end Realtek NICs
    - Often work for light lab use but may struggle at higher traffic rates or inline IPS, and some users report crashes or poor performance.[^3_4][^3_2]
    - Limited queues and weaker drivers reduce Suricata’s ability to scale across CPU cores.[^3_7][^3_3]
- NICs without good Linux drivers or Netfilter/XDP support
    - For advanced modes (AF‑Packet, NFQUEUE, XDP), driver maturity and offload handling matter more than raw specs.[^3_8][^3_6][^3_7]
    - Cheap, no‑name multi‑port NICs can be risky unless they clearly use known chipsets like Intel i350.[^3_1][^3_2]

***

## Configuration tips for better capture

- **Disable problematic offloads** (checksum, TSO/GRO/LRO) on capture interfaces so Suricata sees correct packets:
    - Example pattern with `ethtool` is recommended in Suricata docs for eBPF/XDP and AF‑Packet.[^3_9][^3_8]
- Prefer NICs with **multiple hardware queues** and bind Suricata worker threads to cores for better throughput.[^3_7][^3_5]
- For Kali on a single host, a dual‑port **Intel i210 or i350‑T2** is a strong, cost‑effective choice; for lab 10G, look at **Mellanox ConnectX‑3/4 or Chelsio T4/T5**.[^3_2][^3_5][^3_1]

If you share your expected link speed (e.g., 100 Mbps, 1 Gbps, 10 Gbps) and whether you want IDS only or inline IPS, a specific model recommendation can be narrowed down.
<span style="display:none">[^3_10][^3_11][^3_12][^3_13]</span>

<div align="center">⁂</div>

[^3_1]: https://forum.suricata.io/t/a-question-about-choosing-a-network-card/3976

[^3_2]: https://forum.netgate.com/topic/112728/2-4-suricata-inline-nic-recommendation

[^3_3]: https://www.reddit.com/r/PFSENSE/comments/dh7nhu/what_hw_spec_required_to_run_suricata_ntopng/

[^3_4]: https://forum.netgate.com/topic/119802/hardware-reqs-for-heavy-suricata

[^3_5]: https://suricon.net/wp-content/uploads/2019/11/SURICON2019_Pushing-Suricata-Towards-90-Gbit_s-and-More.pdf

[^3_6]: https://docs.suricata.io/en/suricata-8.0.0/capture-hardware/ebpf-xdp.html

[^3_7]: https://docs.suricata.io/en/latest/performance/high-performance-config.html

[^3_8]: https://redmine.openinfosecfoundation.org/issues/2218

[^3_9]: https://suricataja.readthedocs.io/en/latest/capture-hardware/ebpf-xdp.html

[^3_10]: https://www.digitalocean.com/community/tutorials/how-to-configure-suricata-as-an-intrusion-prevention-system-ips-on-debian-11

[^3_11]: https://cloud-courses.upb.ro/docs/security/ids/

[^3_12]: https://www.reddit.com/r/opnsense/comments/13bjepv/suricata_how_does_it_work_what_rulesets_should_be/

[^3_13]: https://wafatech.sa/blog/linux/linux-security/comprehensive-guide-to-setting-up-suricata-ids-ips-on-your-linux-server/

