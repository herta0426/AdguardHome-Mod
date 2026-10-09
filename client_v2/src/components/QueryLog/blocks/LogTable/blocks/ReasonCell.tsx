import cn from 'clsx';

import theme from 'panel/lib/theme';
import { Filter } from 'panel/helpers/helpers';
import type { NormalizedQueryLogItem } from 'panel/helpers/helpers';
import {
    getQueryReasonLabel,
    getQueryReasonDetails,
    getQueryReasonKey,
} from 'panel/components/QueryLog/helpers';

import s from '../LogTable.module.pcss';

type Props = {
    row: NormalizedQueryLogItem;
    filters: Filter[];
    whitelistFilters: Filter[];
};

export const ReasonCell = (props: Props) => {
    const rules = () => props.row.rules ?? [];
    const reasonKey = () => getQueryReasonKey(props.row.reason, rules());
    const reasonDetails = () =>
        getQueryReasonDetails({
            elapsedMs: props.row.elapsedMs,
            filters: props.filters,
            reason: props.row.reason,
            rules: rules(),
            whitelistFilters: props.whitelistFilters,
        });
    const reasonLabel = () => getQueryReasonLabel(reasonKey());

    return (
        <div class={s.reasonCell}>
            <span class={cn(theme.text.t3, s.reasonLabel)}>{reasonLabel()}</span>
            <span class={cn(s.secondaryLine, theme.text.t4)} title={reasonDetails() || undefined}>
                {reasonDetails()}
            </span>
        </div>
    );
};
