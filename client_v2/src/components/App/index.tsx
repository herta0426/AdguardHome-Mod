import { createEffect, onMount, onCleanup, Show } from 'solid-js';
import { HashRouter, Route, Navigate } from '@solidjs/router';

import { Sidebar } from 'panel/common/ui/Sidebar';
import { Icons } from 'panel/common/ui/Icons';
import { Footer } from 'panel/common/ui/Footer';
import { Header } from 'panel/common/ui/Header';
import { Banners } from 'panel/common/ui/Banners';
import { Settings } from 'panel/components/Settings';
import intl, { LocalesType } from 'panel/common/intl';
import { Blocklists } from 'panel/components/FilterLists/Blocklists';
import { LOCAL_STORAGE_KEYS, LocalStorageHelper } from 'panel/helpers/localStorageHelper';

import { Allowlists } from 'panel/components/FilterLists/Allowlists';
import { DNSRewrites } from 'panel/components/FilterLists/DNSRewrites';
import { Dashboard } from 'panel/components/Dashboard';
import { QueryLog } from 'panel/components/QueryLog';
import { Toasts } from 'panel/components/Toasts';
import { THEMES } from '../../helpers/constants';
import { setHtmlLangAttr, setUITheme } from '../../helpers/helpers';
import { getDnsStatus, getTimerStatus, dashboardState } from '../../stores/dashboard';

import s from './styles.module.pcss';
import { DnsSettings } from '../DnsSettings';
import { PrivateReverse } from '../DnsSettings/PrivateReverse';
import { UserRules } from '../UserRules';
import { Paths } from '../Routes/Paths';
import {
    TopQueriedDomainsPage,
    TopBlockedDomainsPage,
    TopUpstreamsPage,
    UpstreamAvgTimePage,
} from '../Stats';

const App = () => {
    onMount(() => {
        getDnsStatus();

        const handleVisibilityChange = () => {
            if (document.visibilityState === 'visible') {
                getTimerStatus();
            }
        };

        document.addEventListener('visibilitychange', handleVisibilityChange);

        onCleanup(() => {
            document.removeEventListener('visibilitychange', handleVisibilityChange);
        });
    });

    // React to language changes
    createEffect(() => {
        const language = dashboardState.language;
        const processing = dashboardState.processing;
        if (!processing && language) {
            intl.changeLanguage(language as LocalesType).then(() => {
                setHtmlLangAttr(language);
                LocalStorageHelper.setItem(LOCAL_STORAGE_KEYS.LANGUAGE, language);
            });
        }
    });

    // React to theme changes
    createEffect(() => {
        const theme = dashboardState.theme;

        if (!theme) return;

        if (theme !== THEMES.auto) {
            setUITheme(theme);
            return;
        }

        const colorSchemeMedia = window.matchMedia('(prefers-color-scheme: dark)');
        setUITheme(theme);

        const handleChange = (e: MediaQueryListEvent) => {
            if (e.matches) {
                setUITheme(THEMES.dark);
            } else {
                setUITheme(THEMES.light);
            }
        };

        colorSchemeMedia.addEventListener('change', handleChange);
        onCleanup(() => {
            colorSchemeMedia.removeEventListener('change', handleChange);
        });
    });

    return (
        <HashRouter
            root={(props) => (
                <>
                    <Header />

                    <Banners />

                    <div class={s.wrapper}>
                        <Sidebar />

                        <Show when={!dashboardState.processing && dashboardState.isCoreRunning}>
                            <div class={s.bodyWrapper}>{props.children}</div>
                        </Show>
                    </div>

                    <Footer />

                    <Toasts />

                    <Icons />
                </>
            )}
        >
            <Route path={Paths.Dashboard} component={Dashboard} />
            <Route path={Paths.TopQueriedDomains} component={TopQueriedDomainsPage} />
            <Route path={Paths.TopBlockedDomains} component={TopBlockedDomainsPage} />
            <Route path={Paths.TopUpstreams} component={TopUpstreamsPage} />
            <Route path={Paths.UpstreamAvgTime} component={UpstreamAvgTimePage} />
            <Route path={Paths.SettingsPage} component={Settings} />
            <Route path={Paths.Dns} component={DnsSettings} />
            <Route path={Paths.DnsPrivateReverse} component={PrivateReverse} />
            <Route path={Paths.DnsBlocklists} component={Blocklists} />
            <Route path={Paths.DnsAllowlists} component={Allowlists} />
            <Route path={Paths.CustomRules} component={UserRules} />
            <Route path={Paths.DnsRewrites} component={DNSRewrites} />
            <Route path={Paths.Logs} component={QueryLog} />
            <Route path="/" component={() => <Navigate href="/dashboard" />} />
        </HashRouter>
    );
};

export default App;
