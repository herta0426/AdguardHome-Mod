import { Client, RootState } from 'panel/initialState';

import { CheckResultData, ResultActionKind, RewriteEntry } from './types';

export const CLIENT_SCOPED_ACTIONS: ResultActionKind[] = [
    'disable-parental',
    'disable-safebrowsing',
];

export const getPrimaryRule = (result?: CheckResultData | null) => result?.rules?.[0];

const normalizeClientIdentifier = (value: string) => value.trim().toLowerCase();

export const findPersistentClient = (clients: Client[], identifier?: string) => {
    if (!identifier) {
        return undefined;
    }

    const normalizedIdentifier = normalizeClientIdentifier(identifier);
    const matches = clients.filter((client) => {
        if (normalizeClientIdentifier(client.name ?? '') === normalizedIdentifier) {
            return true;
        }

        return (client.ids ?? []).some(
            (clientId) => normalizeClientIdentifier(clientId) === normalizedIdentifier,
        );
    });

    return matches.length === 1 ? matches[0] : undefined;
};

export const getEffectiveClientProtectionSettings = ({
    client,
    globalFilteringEnabled,
    settingsList,
}: {
    client: Client;
    globalFilteringEnabled: boolean;
    settingsList?: RootState['settings']['settingsList'];
}) => {
    if (client.use_global_settings && !settingsList) {
        return null;
    }

    return {
        filtering_enabled: client.use_global_settings
            ? globalFilteringEnabled
            : client.filtering_enabled,
        parental_enabled: client.use_global_settings
            ? Boolean(settingsList?.parental.enabled)
            : client.parental_enabled,
        safebrowsing_enabled: client.use_global_settings
            ? Boolean(settingsList?.safebrowsing.enabled)
            : client.safebrowsing_enabled,
    };
};

const matchesDomain = (hostname: string, pattern: string): boolean => {
    const h = hostname.toLowerCase();
    const p = pattern.toLowerCase();

    if (p === h) {
        return true;
    }

    return p.startsWith('*.') && h.endsWith(p.slice(1));
};

export const findMatchedRewrite = (
    rewrites: RootState['rewrites']['list'],
    checkResult?: CheckResultData | null,
): RewriteEntry | null => {
    if (!checkResult?.hostname) {
        return null;
    }

    const matches = rewrites.filter((entry) => matchesDomain(checkResult.hostname!, entry.domain));

    return matches.length === 1 ? matches[0] : null;
};

