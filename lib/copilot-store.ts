import { create } from 'zustand';

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
}

export const useCopilotStore = create<CopilotState>((set) => ({
  isOpen: true,
  messages: [
    {
      id: '1',
      role: 'assistant',
      content: "I'm your AI Security Assistant. I can help you analyze incidents, search for related alerts, summarize attack chains, and provide security insights. What would you like to investigate?",
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
          content: "I'm your AI Security Assistant. I can help you analyze incidents, search for related alerts, summarize attack chains, and provide security insights. What would you like to investigate?",
          timestamp: new Date(),
        },
      ],
    }),
}));
