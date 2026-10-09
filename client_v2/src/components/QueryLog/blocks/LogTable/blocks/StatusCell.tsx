import { createMemo } from 'solid-js';
import cn from 'clsx';

import theme from 'panel/lib/theme';
import type { NormalizedQueryLogItem } from 'panel/helpers/helpers';
import {
    getQueryStatusDetails,
    getStatusLabel,
    getStatusClassName,
} from 'panel/components/QueryLog/helpers';

import s from '../LogTable.module.pcss';

type Props = {
    row: NormalizedQueryLogItem;
};

export const StatusCell = (props: Props) => {
    const statusLabel = createMemo(() =>
        getStatusLabel(props.row.reason, props.row.originalResponse ?? [], false),
    );

    return (
        <div class={s.statusCell}>
            <span class={cn(s.status, getStatusClassName(props.row.reason), theme.text.t3)}>
                {statusLabel()}
            </span>
            <span class={cn(s.secondaryLine, theme.text.t4)}>
                {getQueryStatusDetails(props.row.elapsedMs)}
            </span>
        </div>
    );
};
