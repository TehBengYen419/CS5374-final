# CS5374 final project

## Advancing Kernel Control Flow Integrity with eBPF
eBPF (extended Berkeley Packet Filter) subsystem, a dynamic kernel code execution framework in Linux kernel, runs sandboxed programs in privileged contexts. It effectively enhance kernel functionalities safely and efficiently without modifying source code or adding modules.

This project delves into the eBPF subsystem, prized for its flexibility and efficiency. Motivated by its potential, we aim to understand its workings and explore applications. Guided by insights from the eBPF & Networking session at the Linux Plumbers Conference (LPC) in 2023, we target to replicate select approaches showcased therein. Additionally, we aspire to enhance these methodologies with our innovations.

The eBPF (extended Berkeley Packet Filter) subsystem within the Linux kernel facilitates dynamic execution of code in privileged environments, augmenting kernel functionality securely and efficiently without necessitating source code alterations or module additions. Motivated by its potential, this project focuses on understanding and exploring the potential of eBPF. Guided by insights from the eBPF & Networking session at the Linux Plumbers Conference (LPC) in 2023, we target to replicate and refine selected methodologies presented therein. Our current focus lies on implementing and improving eKCFI, as proposed by Jia et al., with the source code available on GitHub.

## Disclaimer
This project is a side initiative developed independently by our team. While it aims to extend and apply concepts from existing research, it is not an official continuation or endorsement of the original work by the primary researchers. We have taken inspiration from their published studies and have sought to explore further potential applications and improvements.

## Acknowledgements
We extend our deepest gratitude to the researchers whose groundbreaking work laid the groundwork for this project. We would like to thank the work presented by Jinghao Jia, Michael V. Le, Salman Ahmed, Dan Williams, Hani Jamjoom, Tianyin Xu

## Reference
- [1] Source code: https://github.com/hardos-ebpf-fuzzing/ekcfi
- [2] Paper: Jinghao Jia, Michael V. Le, Salman Ahmed, Dan Williams, and Hani Jamjoom. 2023. Practical and Flexible Kernel CFI Enforcement using eBPF. In Proceedings of the 1st Workshop on eBPF and Kernel Extensions (eBPF '23). Association for Computing Machinery, New York, NY, USA, 84–85. https://doi.org/10.1145/3609021.3609293
- [3] Conference: https://lpc.events/event/17/sessions/155/#20231113
