import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(() => {
    const base = process.env.VITE_BASE_PATH || '/';
    return {
        plugins: [react()],
        base,
    };
});
