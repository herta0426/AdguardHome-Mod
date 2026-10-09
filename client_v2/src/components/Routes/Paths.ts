import qs from 'qs';

const BasicPath = '/';
const pathBuilder = (path: string) => `${BasicPath}${path}`;

export const RoutePath = {
    Dashboard: 'Dashboard',
    Logs: 'Logs',
    Dns: 'Dns',
    DnsPrivateReverse: 'DnsPrivateReverse',
    SettingsPage: 'SettingsPage',
    DnsBlocklists: 'DnsBlocklists',
    DnsAllowlists: 'DnsAllowlists',
    DnsRewrites: 'DnsRewrites',
    CustomRules: 'CustomRules',
    QueryLog: 'QueryLog',
    TopQueriedDomains: 'TopQueriedDomains',
    TopBlockedDomains: 'TopBlockedDomains',
    TopUpstreams: 'TopUpstreams',
    UpstreamAvgTime: 'UpstreamAvgTime',
} as const;

export type RoutePathKey = keyof typeof RoutePath;

export type QueryParams = Record<string, string | number | boolean>;

/** Query param key used to pass a target element ID for scroll-to-section navigation. */
export const SCROLL_QUERY_KEY = 'section';

export const Paths: Record<RoutePathKey, string> = {
    Dashboard: pathBuilder('dashboard'),
    Logs: pathBuilder('logs'),
    Dns: pathBuilder('dns'),
    DnsPrivateReverse: pathBuilder('dns/private-reverse'),
    SettingsPage: pathBuilder('settings'),
    DnsBlocklists: pathBuilder('blocklists'),
    DnsAllowlists: pathBuilder('allowlists'),
    DnsRewrites: pathBuilder('dns_rewrites'),
    CustomRules: pathBuilder('custom_rules'),
    QueryLog: pathBuilder('logs'),
    TopQueriedDomains: pathBuilder('top_queried_domains'),
    TopBlockedDomains: pathBuilder('top_blocked_domains'),
    TopUpstreams: pathBuilder('top_upstreams'),
    UpstreamAvgTime: pathBuilder('upstream_avg_time'),
};

export type LinkParams = Partial<Record<string, string | number>>;

export const linkPathBuilder = (
    route: RoutePathKey,
    params?: LinkParams,
    query?: Partial<Record<string, string | number | boolean>>,
    hash?: string,
) => {
    let path = Paths[route];
    if (params) {
        Object.keys(params).forEach((key: string) => {
            path = path.replace(`:${key}`, String(params[key]));
        });
    }

    if (query) {
        path += `?${qs.stringify(query)}`;
    }

    if (hash) {
        path += `#${hash}`;
    }

    return path;
};
