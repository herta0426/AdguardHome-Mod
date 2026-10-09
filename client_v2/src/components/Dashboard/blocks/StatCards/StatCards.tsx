import intl from 'panel/common/intl';
import { RoutePath } from 'panel/components/Routes/Paths';
import { QUERY_LOG_REASON_FILTER, QUERY_LOG_STATUS_FILTER } from 'panel/helpers/constants';

import s from '../StatCard/StatCard.module.pcss';
import { StatCard, CARDS_THEME, CARDS_COLORS } from '../StatCard';

type Props = {
    numDnsQueries: number;
    numBlockedFiltering: number;
    dnsQueries: number[];
    blockedFiltering: number[];
    timeUnits: string;
};

export const StatCards = (props: Props) => {
    const blockedPercent = () =>
        props.numDnsQueries > 0 ? (props.numBlockedFiltering / props.numDnsQueries) * 100 : 0;

    return (
        <div class={s.statsCards}>
            <StatCard
                value={props.numDnsQueries}
                label={intl.getMessage('dns_query')}
                data={props.dnsQueries}
                timeUnits={props.timeUnits}
                color={CARDS_COLORS.QUERIES}
                cardTheme={CARDS_THEME.QUERIES}
                linkTo={RoutePath.QueryLog}
            />
            <StatCard
                value={props.numBlockedFiltering}
                label={intl.getMessage('ads_blocked_card')}
                data={props.blockedFiltering}
                timeUnits={props.timeUnits}
                color={CARDS_COLORS.ADS}
                percentValue={blockedPercent()}
                cardTheme={CARDS_THEME.ADS}
                linkTo={RoutePath.QueryLog}
                query={{
                    status: QUERY_LOG_STATUS_FILTER.BLOCKED.QUERY,
                    reason: QUERY_LOG_REASON_FILTER.BLOCKED_BY_FILTER.QUERY,
                }}
            />
        </div>
    );
};
