import { Show } from 'solid-js';
import cn from 'clsx';

import theme from 'panel/lib/theme';
import { Icon } from 'panel/common/ui/Icon';

import intl from 'panel/common/intl';
import { Filter } from 'panel/helpers/helpers';
import {
    formatLogDate,
    formatLogTime,
    getClientLocation,
    getProtocolName,
    getQueryReasonLabel,
    getQueryReasonDetails,
    getQueryReasonKey,
    getStatusLabel,
    getStatusClassName,
    isBlockedReason,
} from '../../helpers';
import type { NormalizedQueryLogItem } from 'panel/helpers/helpers';
import { ActionsMenu } from '../ActionsMenu';

import s from './LogCard.module.pcss';

type Props = {
    entry: NormalizedQueryLogItem;
    filters: Filter[];
    whitelistFilters: Filter[];
    onRowClick: (entry: NormalizedQueryLogItem) => void;
    onBlock: (domain: string) => void;
    onUnblock: (domain: string) => void;
};

export const LogCard = (props: Props) => {
    const displayDomain = () => props.entry.unicodeName || props.entry.domain;
    const proto = () => getProtocolName(props.entry.client_proto, props.entry.reason);
    const clientDetails = () => props.entry.client_info?.name || props.entry.client_id;
    const clientLocation = () => getClientLocation(props.entry.client_info?.whois);
    const reasonKey = () => getQueryReasonKey(props.entry.reason, props.entry.rules ?? []);
    const reasonDetails = () =>
        getQueryReasonDetails({
            elapsedMs: props.entry.elapsedMs,
            filters: props.filters,
            reason: props.entry.reason,
            rules: props.entry.rules ?? [],
            whitelistFilters: props.whitelistFilters,
        });
    const statusLabel = () =>
        getStatusLabel(props.entry.reason, props.entry.originalResponse ?? [], false);
    const reasonLabel = () => getQueryReasonLabel(reasonKey());

    return (
        <div
            class={s.card}
            onClick={() => props.onRowClick(props.entry)}
            data-testid="query-log-card"
        >
            <div class={cn(s.cardBody, theme.table.mobileCard)}>
                <div class={s.cardHeader}>
                    <div class={s.titleBlock}>
                        <div class={s.titleRow}>
                            <span
                                class={cn(
                                    s.domain,
                                    theme.text.t3,
                                    theme.text.condenced,
                                    theme.text.semibold,
                                )}
                                title={displayDomain()}
                            >
                                {displayDomain()}
                            </span>

                            <div class={s.iconsRow}>
                                <span class={s.iconWrapper} aria-hidden="true">
                                    <Icon
                                        icon="tracking"
                                        color={props.entry.tracker ? 'green' : 'gray'}
                                        class={s.icon}
                                    />
                                </span>

                                <Show when={props.entry.answer_dnssec}>
                                    <span class={s.iconWrapper} aria-hidden="true">
                                        <Icon icon="lock" color="green" class={s.icon} />
                                    </span>
                                </Show>
                            </div>
                        </div>

                        <span class={cn(s.typeLine, theme.text.t3, theme.text.condenced)}>
                            {intl.getMessage('type_value', { value: props.entry.type })}
                            {proto() ? `, ${proto()}` : ''}
                        </span>
                    </div>

                    <div class={s.actions} onClick={(e) => e.stopPropagation()}>
                        <ActionsMenu
                            domain={props.entry.domain}
                            onBlock={props.onBlock}
                            onUnblock={props.onUnblock}
                            isBlocked={isBlockedReason(props.entry.reason)}
                            testIdPrefix="query-log-card"
                        />
                    </div>
                </div>

                <div class={s.fieldGrid}>
                    <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                        {intl.getMessage('time_table_header')}
                    </span>
                    <span class={cn(s.fieldValue, theme.text.t3, theme.text.condenced)}>
                        {formatLogDate(props.entry.time)}, {formatLogTime(props.entry.time)}
                    </span>

                    <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                        {intl.getMessage('status_table_header')}
                    </span>
                    <span
                        class={cn(
                            s.status,
                            theme.text.t3,
                            theme.text.condenced,
                            getStatusClassName(props.entry.reason),
                        )}
                    >
                        {statusLabel()}
                    </span>

                    <Show when={reasonKey() !== 'none'}>
                        <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                            {intl.getMessage('reason_table_header')}
                        </span>
                        <span class={cn(s.fieldValue, theme.text.t3, theme.text.condenced)}>
                            {reasonLabel()}
                            {reasonDetails() ? ` / ${reasonDetails()}` : ''}
                        </span>
                    </Show>

                    <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                        {intl.getMessage('client_ip')}
                    </span>
                    <span class={cn(s.fieldValue, theme.text.t3, theme.text.condenced)}>
                        {props.entry.client}
                    </span>

                    <Show when={props.entry.destination}>
                        <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                            {intl.getMessage('destination')}
                        </span>
                        <span class={cn(s.fieldValue, theme.text.t3, theme.text.condenced)}>
                            {props.entry.destination}
                        </span>
                    </Show>

                    <Show when={clientDetails()}>
                        <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                            {intl.getMessage('client_details')}
                        </span>
                        <span class={cn(s.fieldValue, theme.text.t3, theme.text.condenced)}>
                            {clientDetails()}
                        </span>
                    </Show>

                    <Show when={clientLocation()}>
                        <span class={cn(s.fieldLabel, theme.text.t3, theme.text.condenced)}>
                            {intl.getMessage('client_location')}
                        </span>
                        <span class={cn(s.fieldValue, theme.text.t3, theme.text.condenced)}>
                            {clientLocation()}
                        </span>
                    </Show>
                </div>
            </div>
        </div>
    );
};
