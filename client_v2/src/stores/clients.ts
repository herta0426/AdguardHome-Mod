import { createStore } from 'solid-js/store';
import { untrack } from 'solid-js';
import { clientsUpdate } from 'panel/api/generated';
import { addErrorToast } from './toasts';
import { getClients } from './dashboard';
import type { Client } from 'panel/api/model/client';

type ClientsState = {
    processing: boolean;
    processingAdding: boolean;
    processingDeleting: boolean;
    processingUpdating: boolean;
    isModalOpen: boolean;
    modalClientName: string;
    modalType: string;
};

const initialState: ClientsState = {
    processing: true,
    processingAdding: false,
    processingDeleting: false,
    processingUpdating: false,
    isModalOpen: false,
    modalClientName: '',
    modalType: '',
};

const [state, setState] = createStore<ClientsState>(initialState);

export const toggleClientModal = (payload?: { type?: string; name?: string }) => {
    if (payload) {
        setState({
            modalType: payload.type || '',
            modalClientName: payload.name || '',
            isModalOpen: !untrack(() => state.isModalOpen),
        });
    } else {
        setState('isModalOpen', (prev) => !prev);
    }
};


export const updateClient = async (name: string, data: Client): Promise<boolean> => {
    setState('processingUpdating', true);
    try {
        await clientsUpdate({ name, data });
        setState('processingUpdating', false);
        toggleClientModal();
        await getClients();
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingUpdating', false);
        return false;
    }
};

export const clientsState = untrack(() => state);
