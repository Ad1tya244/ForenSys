import { create } from 'zustand';
import { useAppStore } from './app-store';

export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface CopilotState {
  isOpen: boolean;
  messages: Message[];
  isLoading: boolean;
  toggleSidebar: () => void;
  addMessage: (role: 'user' | 'assistant', content: string) => void;
  setLoading: (loading: boolean) => void;
  clearMessages: () => void;
  sendMessage: (text: string) => Promise<void>;
}

export const useCopilotStore = create<CopilotState>((set, get) => ({
  isOpen: false,
  messages: [
    {
      id: '1',
      role: 'assistant',
      content: "Hi, I’m Iris, your AI Security Assistant. How can I assist you today?",
      timestamp: new Date(),
    },
  ],
  isLoading: false,
  toggleSidebar: () => set((state) => ({ isOpen: !state.isOpen })),
  addMessage: (role, content) =>
    set((state) => ({
      messages: [
        ...state.messages,
        {
          id: `${Date.now()}`,
          role,
          content,
          timestamp: new Date(),
        },
      ],
    })),
  setLoading: (loading) => set({ isLoading: loading }),
  clearMessages: () =>
    set({
      messages: [
        {
          id: '1',
          role: 'assistant',
          content: "Hi, I’m Iris, your AI Security Assistant. How can I assist you today?",
          timestamp: new Date(),
        },
      ],
    }),
  sendMessage: async (text: string) => {
    const { addMessage, setLoading, isOpen, messages } = get();
    if (!text.trim()) return;

    if (!isOpen) {
      set({ isOpen: true });
    }

    addMessage('user', text);
    setLoading(true);

    const { alerts, incidents, metrics } = useAppStore.getState();

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text,
          history: messages,
          alerts,
          incidents,
          metrics,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.statusText}`);
      }

      const data = await response.json();
      if (data.success) {
        addMessage('assistant', data.response);
      } else {
        throw new Error(data.error || 'Failed to generate response');
      }
    } catch (err: any) {
      console.error(err);
      addMessage('assistant', `⚠️ **Error communicating with AI Assistant:**\n${err.message || 'Unknown error occurred.'}`);
    } finally {
      setLoading(false);
    }
  },
}));
