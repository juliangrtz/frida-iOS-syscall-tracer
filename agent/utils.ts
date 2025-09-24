export function bufToHexStr(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
}