/**
 * Request filtering status.
 */
export type FilteringReason =
    | 'NotFilteredNotFound'
    | 'NotFilteredWhiteList'
    | 'NotFilteredError'
    | 'FilteredBlackList'
    | 'FilteredSafeBrowsing'
    | 'FilteredParental'
    | 'FilteredInvalid'
    | 'Rewrite'
    | 'RewriteEtcHosts'
    | 'RewriteRule'
    | 'FilteredSNI'
    | 'NotFilteredSNI';
