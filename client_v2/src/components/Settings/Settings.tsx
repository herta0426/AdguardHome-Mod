import { createMemo, createEffect, onMount, Show } from 'solid-js';
import { createSignal } from 'solid-js';
import cn from 'clsx';

import { SCROLL_QUERY_KEY } from 'panel/components/Routes/Paths';

import { useSearchParams } from '@solidjs/router';

import intl from 'panel/common/intl';
import { Button } from 'panel/common/ui/Button';
import { ConfirmDialog } from 'panel/common/ui/ConfirmDialog';
import theme from 'panel/lib/theme';
import { PageLoader } from 'panel/common/ui/Loader';
import { getStatsConfig, setStatsConfig, resetStats, statsState } from 'panel/stores/stats';
import { getLogsConfig, setLogsConfig, clearLogs, queryLogsState } from 'panel/stores/queryLogs';
import { addSuccessToast } from 'panel/stores/toasts';

import { SettingRow } from 'panel/common/ui/SettingRow';
import { StatsConfig } from './StatsConfig';
import { LogsConfig } from './LogsConfig';
import { IgnoredDomainsModal } from './IgnoredDomainsModal';
import { getRetentionSummary, buildQueryLogConfig, buildStatsConfig } from './helpers';

import s from './Settings.module.pcss';

export const Settings = () => {
    onMount(() => {
        getStatsConfig();
        getLogsConfig();
    });

    const [logsModalOpen, setLogsModalOpen] = createSignal(false);
    const [statsModalOpen, setStatsModalOpen] = createSignal(false);
    const [showClearLogsConfirm, setShowClearLogsConfirm] = createSignal(false);
    const [showClearStatsConfirm, setShowClearStatsConfirm] = createSignal(false);
    const [logsIgnoredModalOpen, setLogsIgnoredModalOpen] = createSignal(false);
    const [statsIgnoredModalOpen, setStatsIgnoredModalOpen] = createSignal(false);

    const logsRetentionSummary = createMemo(() => getRetentionSummary(queryLogsState.interval));

    const statsRetentionSummary = createMemo(() => getRetentionSummary(statsState.interval));

    const logsIgnoredSummary = createMemo(() => {
        const ignored = queryLogsState.ignored;
        if (!ignored || ignored.length === 0) return '';
        return ignored.join(', ');
    });

    const statsIgnoredSummary = createMemo(() => {
        const ignored = statsState.ignored;
        if (!ignored || ignored.length === 0) return '';
        return ignored.join(', ');
    });

    // Handler functions
    const handleLogsIgnoredSave = (ignored: string[]) => {
        setLogsConfig(buildQueryLogConfig(queryLogsState, { ignored })).then((result) => {
            if (result) {
                setLogsIgnoredModalOpen(false);
                addSuccessToast(intl.getMessage('changes_saved_success'));
            }
        });
    };

    const handleClearLogs = () => {
        clearLogs().then(() => {
            setShowClearLogsConfirm(false);
        });
    };

    const handleStatsIgnoredSave = (ignored: string[]) => {
        setStatsConfig(buildStatsConfig(statsState, { ignored })).then((result) => {
            if (result) {
                setStatsIgnoredModalOpen(false);
                addSuccessToast(intl.getMessage('changes_saved_success'));
            }
        });
    };

    const handleClearStats = () => {
        resetStats().then(() => {
            setShowClearStatsConfirm(false);
        });
    };

    const isLoading = createMemo(() => {
        return !statsState.configInitialized || !queryLogsState.configInitialized;
    });

    const [searchParams] = useSearchParams<{ [SCROLL_QUERY_KEY]?: string }>();

    createEffect(() => {
        if (!isLoading()) {
            const section = searchParams[SCROLL_QUERY_KEY];
            if (section) {
                requestAnimationFrame(() => {
                    const el = document.getElementById(section);
                    if (el) {
                        const top = el.getBoundingClientRect().top + window.scrollY - 80;
                        window.scrollTo({ top, behavior: 'smooth' });
                    }
                });
            }
        }
    });

    return (
        <div class={theme.layout.container}>
            <div class={cn(theme.layout.containerIn, theme.layout.containerIn_one_col)}>
                <h1 class={cn(theme.layout.title, theme.title.h4, theme.title.h3_tablet, s.title)}>
                    {intl.getMessage('settings_general_short')}
                </h1>

                <Show
                    when={isLoading()}
                    fallback={
                        <>
                            <div class={s.section} id="query-log">
                                <SettingRow
                                    variant="switch"
                                    id="querylog_enabled"
                                    title={intl.getMessage('query_log')}
                                    titleClass={cn(
                                        theme.title.h5,
                                        theme.title.h4_tablet,
                                        theme.text.bold,
                                        s.sectionTitle,
                                    )}
                                    align="center"
                                    checked={queryLogsState.enabled}
                                    onChange={(v) =>
                                        setLogsConfig(
                                            buildQueryLogConfig(queryLogsState, { enabled: v }),
                                        )
                                    }
                                    inputClass={s.queryLogSwitch}
                                />

                                <SettingRow
                                    variant="switch"
                                    id="querylog_anonymize"
                                    title={intl.getMessage('settings_anonymize_client_ip')}
                                    description={intl.getMessage(
                                        'settings_anonymize_client_ip_desc',
                                    )}
                                    checked={queryLogsState.anonymize_client_ip}
                                    disabled={!queryLogsState.enabled}
                                    onChange={(v) =>
                                        setLogsConfig(
                                            buildQueryLogConfig(queryLogsState, {
                                                anonymize_client_ip: v,
                                            }),
                                        )
                                    }
                                />

                                <SettingRow
                                    variant="link"
                                    id="querylog_retention"
                                    title={intl.getMessage('query_log_retention')}
                                    value={logsRetentionSummary()}
                                    disabled={!queryLogsState.enabled}
                                    onClick={() => setLogsModalOpen(true)}
                                />

                                <SettingRow
                                    variant="switch-link"
                                    id="querylog_ignored"
                                    title={intl.getMessage('ignore_domains_title')}
                                    description={intl.getMessage('ignore_domains_desc_log')}
                                    checked={queryLogsState.ignored_enabled}
                                    value={logsIgnoredSummary()}
                                    divider
                                    disabled={!queryLogsState.enabled}
                                    onChange={(v) =>
                                        setLogsConfig(
                                            buildQueryLogConfig(queryLogsState, {
                                                ignored_enabled: v,
                                            }),
                                        )
                                    }
                                    onClick={() => setLogsIgnoredModalOpen(true)}
                                />

                                <div class={s.actionRow}>
                                    <Button
                                        variant="secondary-danger"
                                        class={s.clearButton}
                                        onClick={() => setShowClearLogsConfirm(true)}
                                        compact
                                    >
                                        {intl.getMessage('clear_query_log')}
                                    </Button>
                                </div>
                            </div>

                            <LogsConfig
                                interval={queryLogsState.interval}
                                customInterval={queryLogsState.customInterval}
                                processing={queryLogsState.processingSetConfig}
                                modalOpen={logsModalOpen()}
                                onModalClose={() => setLogsModalOpen(false)}
                            />

                            <IgnoredDomainsModal
                                open={logsIgnoredModalOpen()}
                                title={intl.getMessage('ignore_domains_title')}
                                ignored={queryLogsState.ignored}
                                processing={queryLogsState.processingSetConfig}
                                onClose={() => setLogsIgnoredModalOpen(false)}
                                onSave={handleLogsIgnoredSave}
                            />

                            <Show when={showClearLogsConfirm()}>
                                <ConfirmDialog
                                    title={intl.getMessage('settings_confirm_clear_query_log')}
                                    text={intl.getMessage('settings_confirm_clear_query_log_desc')}
                                    buttonText={intl.getMessage('settings_yes_clear')}
                                    cancelText={intl.getMessage('cancel')}
                                    buttonVariant="danger"
                                    onClose={() => setShowClearLogsConfirm(false)}
                                    onConfirm={handleClearLogs}
                                />
                            </Show>

                            <div class={s.section} id="statistics">
                                <SettingRow
                                    variant="switch"
                                    id="stats_enabled"
                                    title={intl.getMessage('settings_statistics')}
                                    description={intl.getMessage('settings_statistics_desc')}
                                    titleClass={cn(
                                        theme.title.h5,
                                        theme.title.h4_tablet,
                                        theme.text.bold,
                                        s.statsTitle,
                                    )}
                                    checked={statsState.enabled}
                                    onChange={(v) =>
                                        setStatsConfig(buildStatsConfig(statsState, { enabled: v }))
                                    }
                                />

                                <SettingRow
                                    variant="link"
                                    id="stats_retention"
                                    title={intl.getMessage('settings_statistics_retention')}
                                    value={statsRetentionSummary()}
                                    disabled={!statsState.enabled}
                                    onClick={() => setStatsModalOpen(true)}
                                />

                                <SettingRow
                                    variant="switch-link"
                                    id="stats_ignored"
                                    title={intl.getMessage('ignore_domains_title')}
                                    description={intl.getMessage('ignore_domains_desc_stats')}
                                    checked={statsState.ignored_enabled}
                                    value={statsIgnoredSummary()}
                                    divider
                                    disabled={!statsState.enabled}
                                    onChange={(v) =>
                                        setStatsConfig(
                                            buildStatsConfig(statsState, { ignored_enabled: v }),
                                        )
                                    }
                                    onClick={() => setStatsIgnoredModalOpen(true)}
                                />

                                <div class={s.actionRow}>
                                    <Button
                                        variant="secondary-danger"
                                        class={s.clearButton}
                                        onClick={() => setShowClearStatsConfirm(true)}
                                        compact
                                    >
                                        {intl.getMessage('settings_statistics_clear')}
                                    </Button>
                                </div>

                                <StatsConfig
                                    interval={statsState.interval}
                                    customInterval={statsState.customInterval}
                                    processing={statsState.processingSetConfig}
                                    modalOpen={statsModalOpen()}
                                    onModalClose={() => setStatsModalOpen(false)}
                                />

                                <IgnoredDomainsModal
                                    open={statsIgnoredModalOpen()}
                                    title={intl.getMessage('ignore_domains_title')}
                                    ignored={statsState.ignored}
                                    processing={statsState.processingSetConfig}
                                    onClose={() => setStatsIgnoredModalOpen(false)}
                                    onSave={handleStatsIgnoredSave}
                                />

                                <Show when={showClearStatsConfirm()}>
                                    <ConfirmDialog
                                        title={intl.getMessage('settings_confirm_clear_statistics')}
                                        text={intl.getMessage(
                                            'settings_confirm_clear_statistics_desc',
                                        )}
                                        buttonText={intl.getMessage('settings_yes_clear')}
                                        cancelText={intl.getMessage('cancel')}
                                        buttonVariant="danger"
                                        onClose={() => setShowClearStatsConfirm(false)}
                                        onConfirm={handleClearStats}
                                    />
                                </Show>
                            </div>
                        </>
                    }
                >
                    <PageLoader />
                </Show>
            </div>
        </div>
    );
};
