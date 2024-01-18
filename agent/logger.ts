// ANSI colors
// https://stackoverflow.com/questions/9781218/how-to-change-node-jss-console-font-color
export const Color = {
    Reset: "\x1b[0m",
    Black: "\x1b[30m",
    White: "\x1b[37m",
    Blue: "\x1b[44m",
    Cyan: "\x1b[36m",
    Green: "\x1b[32m",
    Magenta: "\x1b[35m",
    Red: "\x1b[31m",
    Yellow: "\x1b[33m",
};

export function log(input: object | string, color = Color.White) {
    console.log(color +
        `${typeof input == 'object'
            ? JSON.stringify(input)
            : input}${Color.Reset}`
    );
};

export function logInfo(input: object | string) {
    log(input, Color.Reset);
}

export function logWarning(input: object | string) {
    log(input, Color.Yellow);
}

export function logError(input: object | string) {
    log(input, Color.Red);
}
