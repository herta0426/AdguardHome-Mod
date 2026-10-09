import type { QueryReasonKey } from '../../helpers';

export type DetailModalActionId =
    | 'block'
    | 'add-to-allowlist'
    | 'disable-filter'
    | 'disable-browsing-security'
    | 'disable-parental'
    | 'remove-dns-rewrite'
    | 'edit-dns-rewrite';

export type DetailModalActionContext = {
    /** A filter list matching rules[*].filter_list_id was found in `filters`. */
    canDisableFilter: boolean;
    /** A rewrite rule matching the entry domain was found. */
    hasRewriteRule: boolean;
};

/** Status → ordered actions (primary first, secondary second). */
export const getDetailModalActions = (
    reason: QueryReasonKey,
    ctx: DetailModalActionContext,
): DetailModalActionId[] => {
    switch (reason) {
        case 'allowlists':
            return ['block'];
        case 'none':
            return ['add-to-allowlist', 'block'];
        case 'blocked_threats':
            return ['add-to-allowlist', 'disable-browsing-security'];
        case 'blocked_by_parental_control':
            return ['add-to-allowlist', 'disable-parental'];
        case 'blocked_by_filter':
            return ctx.canDisableFilter
                ? ['add-to-allowlist', 'disable-filter']
                : ['add-to-allowlist'];
        case 'custom_filtering_rules':
            return ['add-to-allowlist'];
        case 'dns_rewrites':
            return ctx.hasRewriteRule
                ? ['remove-dns-rewrite', 'edit-dns-rewrite']
                : [];
        case 'error':
        default:
            return [];
    }
};
