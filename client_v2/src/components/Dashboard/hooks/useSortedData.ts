import { createMemo } from 'solid-js';

type SortableItem = {
    count: number;
};

export const DEFAULT_VISIBLE_ITEMS = 5;

export const TOP_CLIENTS_VISIBLE_ITEMS = 4;

export const useSortedData = <T extends SortableItem>(
    data: () => T[],
    limit: number = DEFAULT_VISIBLE_ITEMS,
): { sortedData: () => T[]; hasMore: () => boolean } => {
    // `toSorted` is ES2023 (Chrome/WebView 110+) and the browserslist targets
    // do not guarantee it, so copy first — the source may be a store array.
    const sortedData = createMemo(() =>
        [...data()]
            .sort((a, b) => b.count - a.count)
            .slice(0, limit),
    );

    // True when the list is longer than the visible rows, so the card can
    // offer the "Show more" link only when it would reveal something.
    const hasMore = createMemo(() => data().length > limit);

    return { sortedData, hasMore };
};
