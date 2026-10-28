import { describe, it, expect } from 'vitest';
import { createRoot } from 'solid-js';

import {
    TOP_CLIENTS_VISIBLE_ITEMS,
    useSortedData,
} from 'panel/components/Dashboard/hooks/useSortedData';

describe('useSortedData', () => {
    it('sorts by count descending and leaves the source array untouched', () => {
        const source = [{ count: 1 }, { count: 9 }, { count: 5 }];
        const before = source.map((row) => row.count);

        createRoot((dispose) => {
            const { sortedData, hasMore } = useSortedData(() => source);

            expect(sortedData().map((row) => row.count)).toEqual([9, 5, 1]);
            expect(hasMore()).toBe(false);
            dispose();
        });

        // The hook sorts a copy; the array it was given must keep its order.
        expect(source.map((row) => row.count)).toEqual(before);
    });

    it('truncates to the limit and reports when more rows exist', () => {
        const source = [3, 1, 2, 4, 5, 6].map((count) => ({ count }));

        createRoot((dispose) => {
            const { sortedData, hasMore } = useSortedData(
                () => source,
                TOP_CLIENTS_VISIBLE_ITEMS,
            );

            expect(sortedData().map((row) => row.count)).toEqual([6, 5, 4, 3]);
            expect(hasMore()).toBe(true);
            dispose();
        });
    });
});
