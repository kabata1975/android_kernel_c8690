obj-y += io.o idle.o timer.o
obj-y += clock.o
obj-$(CONFIG_DEBUG_FS) += clock-debug.o

obj-$(CONFIG_MSM_VIC) += irq-vic.o
obj-$(CONFIG_MSM_IOMMU) += iommu.o iommu_dev.o devices-iommu.o

obj-$(CONFIG_ARCH_MSM7X00A) += dma.o irq.o acpuclock-arm11.o
obj-$(CONFIG_ARCH_MSM7X30) += dma.o
obj-$(CONFIG_ARCH_QSD8X50) += dma.o sirc.o

obj-$(CONFIG_MSM_PROC_COMM) += proc_comm.o clock-pcom.o vreg.o

obj-$(CONFIG_MSM_SMD) += smd.o smd_debug.o
obj-$(CONFIG_MSM_SMD) += last_radio_log.o
obj-$(CONFIG_MSM_SCM) += scm.o scm-boot.o

obj-$(CONFIG_HOTPLUG_CPU) += hotplug.o
obj-$(CONFIG_SMP) += headsmp.o platsmp.o

obj-$(CONFIG_MACH_TROUT) += board-trout.o board-trout-gpio.o board-trout-mmc.o devices-msm7x00.o
obj-$(CONFIG_MACH_TROUT) += board-trout.o board-trout-gpio.o board-trout-mmc.o board-trout-panel.o devices-msm7x00.o
obj-$(CONFIG_MACH_HALIBUT) += board-halibut.o devices-msm7x00.o
obj-$(CONFIG_ARCH_MSM7X30) += board-msm7x30.o devices-msm7x30.o
obj-$(CONFIG_ARCH_QSD8X50) += board-qsd8x50.o devices-qsd8x50.o
obj-$(CONFIG_ARCH_MSM8X60) += board-msm8x60.o
obj-$(CONFIG_ARCH_MSM8960) += board-msm8960.o devices-msm8960.o

obj-$(CONFIG_ARCH_MSM7X30) += gpiomux-v1.o gpiomux.o
obj-$(CONFIG_ARCH_QSD8X50) += gpiomux-8x50.o gpiomux-v1.o gpiomux.o
obj-$(CONFIG_ARCH_MSM8X60) += gpiomux-8x60.o gpiomux-v2.o gpiomux.o
ifdef CONFIG_MSM_V2_TLMM
ifndef CONFIG_ARCH_MSM8960
# TODO: TLMM Mapping issues need to be resolved
obj-y	+= gpio-v2.o
endif
else
obj-y	+= gpio.o
endif
<<<<<<< HEAD
=======
obj-$(CONFIG_MSM_MPM_OF) += mpm-of.o
obj-$(CONFIG_MSM_RPM_STATS_LOG) += rpm_stats.o rpm_master_stat.o
obj-$(CONFIG_MSM_RPM_RBCPR_STATS_V2_LOG) += rpm_rbcpr_stats_v2.o
obj-$(CONFIG_MSM_RPM_LOG) += rpm_log.o
obj-$(CONFIG_MSM_TZ_LOG) += tz_log.o
obj-$(CONFIG_MSM_BUS_SCALING) += msm_bus/
obj-$(CONFIG_MSM_BUSPM_DEV) += msm-buspm-dev.o

obj-$(CONFIG_MSM_EVENT_TIMER)		+= event_timer.o

obj-$(CONFIG_MSM_OCMEM) += ocmem.o ocmem_allocator.o ocmem_notifier.o
obj-$(CONFIG_MSM_OCMEM) += ocmem_sched.o ocmem_api.o ocmem_rdm.o ocmem_core.o

obj-$(CONFIG_ARCH_MSM8974) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_MDM9630) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_MSMSAMARIUM) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_MPQ8092) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_MSM8226) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_MSM8610) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_APQ8084) += gpiomux-v2.o gpiomux.o
obj-$(CONFIG_ARCH_FSM9900) += gpiomux-v2.o gpiomux.o

obj-$(CONFIG_MSM_RUN_QUEUE_STATS) += msm_rq_stats.o
obj-$(CONFIG_MSM_NATIVE_RESTART) += restart.o

obj-$(CONFIG_MSM_CACHE_ERP) += cache_erp.o
obj-$(CONFIG_MSM_CACHE_DUMP) += msm_cache_dump.o

obj-$(CONFIG_MSM_HSIC_SYSMON) += hsic_sysmon.o
obj-$(CONFIG_MSM_HSIC_SYSMON_TEST) += hsic_sysmon_test.o

obj-$(CONFIG_MSM_RPM_SMD) += rpm-smd.o
obj-$(CONFIG_MSM_RPC_USB) += rpc_hsusb.o rpc_fsusb.o

obj-$(CONFIG_MSM_ENABLE_WDOG_DEBUG_CONTROL) += wdog_debug.o

obj-$(CONFIG_MEMORY_HOLE_CARVEOUT) +=  msm_mem_hole.o

obj-$(CONFIG_MSM_SMCMOD) += smcmod.o

obj-$(CONFIG_ARCH_MSM8974) += msm_mpmctr.o
obj-$(CONFIG_MSM_CPR_REGULATOR) += cpr-regulator.o
obj-$(CONFIG_MSM_DEVFREQ_CPUBW) += devfreq_cpubw.o

obj-$(CONFIG_HAS_MACH_MEMUTILS) += memutils/
obj-$(CONFIG_ARCH_RANDOM) += early_random.o
obj-$(CONFIG_PERFMAP) += perfmap.o
obj-$(CONFIG_EXTCON) += board-extcon-connector.o
obj-$(CONFIG_REGULATOR_MAX77803) += sec-regulator-max77803.o
obj-$(CONFIG_REGULATOR_MAX77828) += sec-regulator-max77828.o


obj-$(CONFIG_SEC_DEBUG) += sec_debug.o sec_gaf.o sec_getlog.o
obj-$(CONFIG_SEC_DEBUG_DOUBLE_FREE) += sec_debug-dfd.o

obj-$(CONFIG_SEC_BSP) += sec_bsp.o

obj-$(CONFIG_SEC_THERMISTOR) += sec_thermistor.o apq8084-thermistor.o
obj-$(CONFIG_BT_BCM4358) += board-bluetooth-bcm4358.o
obj-$(CONFIG_GSM_MODEM_SPRD6500) += board-sprd6500-spi.o board-sprd6500-modems.o

obj-$(CONFIG_INTELLI_HOTPLUG) += intelli_hotplug.o
obj-$(CONFIG_MSM_CPUFREQ_LIMIT) += cpufreq_limit.o
obj-$(CONFIG_FORCE_FAST_CHARGE) += fastchg.o
obj-$(CONFIG_ZEN_DECISION) += msm_zen_decision.o
>>>>>>> a1ced08... msm: add msm_zen_decision (bbedward) This adds a simple driver intended to allow the MPDecision service to be disabled. The driver is easily extendable, but currently it: - Can be enabled/disabled in /sys/kernel/zen_decision/enabled - On screen power OFF it removes all cpu cores after suspend_wait_time - On screen power ON it enables all cpu cores. - /sys/kernel/zen_decision/suspend_wait_time (ms) refers to how long we wait after screen is off to remove the cores (default 5s). This just to avoid removing cores in excess.
