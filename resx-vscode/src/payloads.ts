export function unwrapListPayload<T>(payload: unknown, key: string): T[] {
    if (Array.isArray(payload)) {
        return payload as T[];
    }
    if (payload && typeof payload === 'object') {
        const value = (payload as Record<string, unknown>)[key];
        if (Array.isArray(value)) {
            return value as T[];
        }
    }
    return [];
}

export function unwrapObjectPayload<T>(payload: unknown, key: string): T | null {
    if (!payload || typeof payload !== 'object') {
        return null;
    }
    const record = payload as Record<string, unknown>;
    const nested = record[key];
    if (nested && typeof nested === 'object') {
        return nested as T;
    }
    return record as T;
}
