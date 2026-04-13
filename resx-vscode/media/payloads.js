export function unwrapListPayload(payload, key) {
    if (Array.isArray(payload)) {
        return payload;
    }
    if (payload && typeof payload === 'object') {
        const value = payload[key];
        if (Array.isArray(value)) {
            return value;
        }
    }
    return [];
}
export function unwrapObjectPayload(payload, key) {
    if (!payload || typeof payload !== 'object') {
        return null;
    }
    const record = payload;
    const nested = record[key];
    if (nested && typeof nested === 'object') {
        return nested;
    }
    return record;
}
