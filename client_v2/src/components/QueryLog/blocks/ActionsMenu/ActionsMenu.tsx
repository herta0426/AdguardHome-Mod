import { createSignal } from 'solid-js';
import cn from 'clsx';

import intl from 'panel/common/intl';
import { Dropdown } from 'panel/common/ui/Dropdown';
import { Icon } from 'panel/common/ui/Icon';

import theme from 'panel/lib/theme';
import s from './ActionsMenu.module.pcss';

type Props = {
    domain: string;
    onBlock: (domain: string) => void;
    onUnblock: (domain: string) => void;
    isBlocked: boolean;
    testIdPrefix?: string;
};

export const ActionsMenu = (props: Props) => {
    const [open, setOpen] = createSignal(false);

    const handleBlock = () => {
        if (props.isBlocked) {
            props.onUnblock(props.domain);
        } else {
            props.onBlock(props.domain);
        }
        setOpen(false);
    };

    const menu = (
        <ul
            class={s.menu}
            role="menu"
            data-testid={`${props.testIdPrefix}-actions-menu`}
        >
            <li role="none">
                <button
                    type="button"
                    data-testid={`${props.testIdPrefix}-action-toggle-block`}
                    class={cn(
                        s.menuItem,
                        s.menuButton,
                        theme.text.t3,
                        props.isBlocked ? s.statusGreen : s.statusRed,
                    )}
                    onClick={handleBlock}
                >
                    {props.isBlocked ? intl.getMessage('unblock') : intl.getMessage('block')}
                </button>
            </li>
        </ul>
    );

    return (
        <Dropdown
            menu={menu}
            open={open()}
            onOpenChange={setOpen}
            position="bottomRight"
            noIcon
            overlayClass={s.overlay}
        >
            <button
                type="button"
                class={s.trigger}
                data-testid={`${props.testIdPrefix}-actions-trigger`}
            >
                <Icon icon="bullets" />
            </button>
        </Dropdown>
    );
};
