var commonjsGlobal = typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : {};

function createCommonjsModule(fn, basedir, module) {
    return module = {
        path: basedir,
        exports: {},
        require: function (path, base) {
            return commonjsRequire(path, base === undefined || base === null ? module.path : base)
        }
    }, fn(module, module.exports), module.exports
}

var utils = createCommonjsModule(function (module, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", {
        value: true
    });
    exports.joinSignature = exports.splitSignature = exports.hexZeroPad = exports.hexStripZeros = exports.hexValue = exports.hexConcat = exports.hexDataSlice = exports.hexDataLength = exports.hexlify = exports.isHexString = exports.zeroPad = exports.stripZeros = exports.concat = exports.arrayify = exports.toUtf8Bytes = exports.isBytes = exports.isBytesLike = void 0;

    function isHexable(value) {
        return !!value.toHexString
    }

    function addSlice(array) {
        if (array.slice) {
            return array
        }
        array.slice = function () {
            var args = Array.prototype.slice.call(arguments);
            return addSlice(new Uint8Array(Array.prototype.slice.apply(array, args)))
        };
        return array
    }

    function isBytesLike(value) {
        return isHexString(value) && !(value.length % 2) || isBytes(value)
    }
    exports.isBytesLike = isBytesLike;

    function isBytes(value) {
        if (value == null) {
            return false
        }
        if (value.constructor === Uint8Array) {
            return true
        }
        if (typeof value === "string") {
            return false
        }
        if (value.length == null) {
            return false
        }
        for (var i = 0; i < value.length; i++) {
            var v = value[i];
            if (typeof v !== "number" || v < 0 || v >= 256 || v % 1) {
                return false
            }
        }
        return true
    }
    exports.isBytes = isBytes;

    function checkSafeUint53(value, message) {
        if (typeof value !== "number") {
            return
        }
        if (message == null) {
            message = "value not safe"
        }
        if (value < 0 || value >= 9007199254740991) {
            throw new Error("out-of-safe-range")
        }
        if (value % 1) {
            throw new Error("non-integer")
        }
    }
    exports.checkSafeUint53 = checkSafeUint53;

    function arrayify(value, options) {
        if (!options) {
            options = {}
        }
        if (typeof value === "number") {
            console.log("invalid arrayify value");
            checkSafeUint53(value, "invalid arrayify value");

            var result = [];
            while (value) {
                result.unshift(value & 255);
                value = parseInt(String(value / 256))
            }
            if (result.length === 0) {
                result.push(0)
            }
            return addSlice(new Uint8Array(result))
        }
        if (options.allowMissingPrefix && typeof value === "string" && value.substring(0, 2) !== "0x") {
            value = "0x" + value
        }
        if (isHexable(value)) {
            value = value.toHexString()
        }
        if (isHexString(value)) {
            var hex = value.substring(2);
            if (hex.length % 2) {
                if (options.hexPad === "left") {
                    hex = "0x0" + hex.substring(2)
                } else if (options.hexPad === "right") {
                    hex += "0"
                } else {
                    console.log("hex data is odd-length");
                    throw new Error("hex data is odd-length")
                }
            }
            var result = [];
            for (var i = 0; i < hex.length; i += 2) {
                result.push(parseInt(hex.substring(i, i + 2), 16))
            }
            return addSlice(new Uint8Array(result))
        }
        if (isBytes(value)) {
            return addSlice(new Uint8Array(value))
        }
        console.log("invalid arrayify value");
        throw new Error("invalid arrayify value")
    }
    exports.arrayify = arrayify;


    function toUtf8Bytes(str) {
        var result = [];
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 128) {
                result.push(c)
            } else if (c < 2048) {
                result.push(c >> 6 | 192);
                result.push(c & 63 | 128)
            } else if ((c & 64512) == 55296) {
                i++;
                var c2 = str.charCodeAt(i);
                if (i >= str.length || (c2 & 64512) !== 56320) {
                    throw new Error("invalid utf-8 string")
                }
                var pair = 65536 + ((c & 1023) << 10) + (c2 & 1023);
                result.push(pair >> 18 | 240);
                result.push(pair >> 12 & 63 | 128);
                result.push(pair >> 6 & 63 | 128);
                result.push(pair & 63 | 128)
            } else {
                result.push(c >> 12 | 224);
                result.push(c >> 6 & 63 | 128);
                result.push(c & 63 | 128)
            }
        }
        return arrayify(result)
    }
    exports.toUtf8Bytes = toUtf8Bytes;

    function concat(items) {
        var objects = items.map(function (item) {
            return arrayify(item)
        });
        var length = objects.reduce(function (accum, item) {
            return accum + item.length
        }, 0);
        var result = new Uint8Array(length);
        objects.reduce(function (offset, object) {
            result.set(object, offset);
            return offset + object.length
        }, 0);
        return addSlice(result)
    }
    exports.concat = concat;

    function stripZeros(value) {
        var result = arrayify(value);
        if (result.length === 0) {
            return result
        }
        var start = 0;
        while (start < result.length && result[start] === 0) {
            start++
        }
        if (start) {
            result = result.slice(start)
        }
        return result
    }
    exports.stripZeros = stripZeros;

    function zeroPad(value, length) {
        value = arrayify(value);
        if (value.length > length) {
            console.log("value out of range");
            throw new Error("value out of range")
        }
        var result = new Uint8Array(length);
        result.set(value, length - value.length);
        return addSlice(result)
    }
    exports.zeroPad = zeroPad;

    function isHexString(value, length) {
        if (typeof value !== "string" || !value.match(/^0x[0-9A-Fa-f]*$/)) {
            return false
        }
        if (length && value.length !== 2 + 2 * length) {
            return false
        }
        return true
    }
    exports.isHexString = isHexString;
    var HexCharacters = "0123456789abcdef";

    function hexlify(value, options) {
        if (!options) {
            options = {}
        }
        if (typeof value === "number") {
            console.log("invalid hexlify value");
            checkSafeUint53(value, "invalid hexlify value");
            var hex = "";
            while (value) {
                hex = HexCharacters[value & 15] + hex;
                value = Math.floor(value / 16)
            }
            if (hex.length) {
                if (hex.length % 2) {
                    hex = "0" + hex
                }
                return "0x" + hex
            }
            return "0x00"
        }
        if (typeof value === "bigint") {
            value = value.toString(16);
            if (value.length % 2) {
                return "0x0" + value
            }
            return "0x" + value
        }
        if (options.allowMissingPrefix && typeof value === "string" && value.substring(0, 2) !== "0x") {
            value = "0x" + value
        }
        if (isHexable(value)) {
            return value.toHexString()
        }
        if (isHexString(value)) {
            if (value.length % 2) {
                if (options.hexPad === "left") {
                    value = "0x0" + value.substring(2)
                } else if (options.hexPad === "right") {
                    value += "0"
                } else {
                    console.log("hex data is odd-length");
                    throw new Error("hex data is odd-length")
                }
            }
            return value.toLowerCase()
        }
        if (isBytes(value)) {
            var result = "0x";
            for (var i = 0; i < value.length; i++) {
                var v = value[i];
                result += HexCharacters[(v & 240) >> 4] + HexCharacters[v & 15]
            }
            return result
        }
        console.log("invalid hexlify value");
        throw new Error("invalid hexlify value")
    }
    exports.hexlify = hexlify;

    function hexDataLength(data) {
        if (typeof data !== "string") {
            data = hexlify(data)
        } else if (!isHexString(data) || data.length % 2) {
            return null
        }
        return (data.length - 2) / 2
    }
    exports.hexDataLength = hexDataLength;

    function hexDataSlice(data, offset, endOffset) {
        if (typeof data !== "string") {
            data = hexlify(data)
        } else if (!isHexString(data) || data.length % 2) {
            console.log("invalid hexData");
            throw new Error("invalid hexData")
        }
        offset = 2 + 2 * offset;
        if (endOffset != null) {
            return "0x" + data.substring(offset, 2 + 2 * endOffset)
        }
        return "0x" + data.substring(offset)
    }
    exports.hexDataSlice = hexDataSlice;

    function hexConcat(items) {
        var result = "0x";
        items.forEach(function (item) {
            result += hexlify(item).substring(2)
        });
        return result
    }
    exports.hexConcat = hexConcat;

    function hexValue(value) {
        var trimmed = hexStripZeros(hexlify(value, {
            hexPad: "left"
        }));
        if (trimmed === "0x") {
            return "0x0"
        }
        return trimmed
    }
    exports.hexValue = hexValue;

    function hexStripZeros(value) {
        if (typeof value !== "string") {
            value = hexlify(value)
        }
        if (!isHexString(value)) {
            console.log("invalid hex string");
            throw new Error("invalid hex string")
        }
        value = value.substring(2);
        var offset = 0;
        while (offset < value.length && value[offset] === "0") {
            offset++
        }
        return "0x" + value.substring(offset)
    }
    exports.hexStripZeros = hexStripZeros;

    function hexZeroPad(value, length) {
        if (typeof value !== "string") {
            value = hexlify(value)
        } else if (!isHexString(value)) {
            console.log("invalid hex string");
            throw new Error("invalid hex string")
        }
        if (value.length > 2 * length + 2) {
            console.log("value out of range");
            throw new Error("value out of range")
        }
        while (value.length < 2 * length + 2) {
            value = "0x0" + value.substring(2)
        }
        return value
    }
    exports.hexZeroPad = hexZeroPad;

    function splitSignature(signature) {
        var result = {
            r: "0x",
            s: "0x",
            _vs: "0x",
            recoveryParam: 0,
            v: 0
        };
        if (isBytesLike(signature)) {
            var bytes = arrayify(signature);
            if (bytes.length !== 65) {
                console.log("invalid signature string; must be 65 bytes");
                throw new Error("invalid signature string; must be 65 bytes")
            }
            result.r = hexlify(bytes.slice(0, 32));
            result.s = hexlify(bytes.slice(32, 64));
            result.v = bytes[64];
            if (result.v < 27) {
                if (result.v === 0 || result.v === 1) {
                    result.v += 27
                } else {
                    console.log("signature invalid v byte");
                    throw new Error("signature invalid v byte")
                }
            }
            result.recoveryParam = 1 - result.v % 2;
            if (result.recoveryParam) {
                bytes[32] |= 128
            }
            result._vs = hexlify(bytes.slice(32, 64))
        } else {
            result.r = signature.r;
            result.s = signature.s;
            result.v = signature.v;
            result.recoveryParam = signature.recoveryParam;
            result._vs = signature._vs;
            if (result._vs != null) {
                var vs_1 = zeroPad(arrayify(result._vs), 32);
                result._vs = hexlify(vs_1);
                var recoveryParam = vs_1[0] >= 128 ? 1 : 0;
                if (result.recoveryParam == null) {
                    result.recoveryParam = recoveryParam
                } else if (result.recoveryParam !== recoveryParam) {
                    console.log("signature recoveryParam mismatch _vs");
                    throw new Error("signature recoveryParam mismatch _vs")
                }
                vs_1[0] &= 127;
                var s = hexlify(vs_1);
                if (result.s == null) {
                    result.s = s
                } else if (result.s !== s) {
                    console.log("signature v mismatch _vs");
                    throw new Error("signature v mismatch _vs")
                }
            }
            if (result.recoveryParam == null) {
                if (result.v == null) {
                    console.log("signature missing v and recoveryParam");
                    throw new Error("signature missing v and recoveryParam")
                } else if (result.v === 0 || result.v === 1) {
                    result.recoveryParam = result.v
                } else {
                    result.recoveryParam = 1 - result.v % 2
                }
            } else {
                if (result.v == null) {
                    result.v = 27 + result.recoveryParam
                } else if (result.recoveryParam !== 1 - result.v % 2) {
                    console.log("signature v mismatch _vs");
                    throw new Error("signature v mismatch _vs")
                }
            }
            if (result.r == null || !isHexString(result.r)) {
                console.log("signature missing or invalid r");
                throw new Error("signature missing or invalid r")
            } else {
                result.r = hexZeroPad(result.r, 32)
            }
            if (result.s == null || !isHexString(result.s)) {
                console.log("signature missing or invalid s");
                throw new Error("signature missing or invalid s")
            } else {
                result.s = hexZeroPad(result.s, 32)
            }
            var vs = arrayify(result.s);
            if (vs[0] >= 128) {
                console.log("signature s out of range");
                throw new Error("signature s out of range")
            }
            if (result.recoveryParam) {
                vs[0] |= 128
            }
            var _vs = hexlify(vs);
            if (result._vs) {
                if (!isHexString(result._vs)) {
                    console.log("signature invalid _vs");
                    throw new Error("signature invalid _vs")
                }
                result._vs = hexZeroPad(result._vs, 32)
            }
            if (result._vs == null) {
                result._vs = _vs
            } else if (result._vs !== _vs) {
                console.log("signature _vs mismatch v and s");
                throw new Error("signature _vs mismatch v and s")
            }
        }
        return result
    }
    exports.splitSignature = splitSignature;

    function joinSignature(signature) {
        signature = splitSignature(signature);
        return hexlify(concat([signature.r, signature.s, signature.recoveryParam ? "0x1c" : "0x1b"]))
    }
    exports.joinSignature = joinSignature
});

var sha3 = createCommonjsModule(function (module) {
    (function () {
        "use strict";
        var root = typeof window === "object" ? window : {};
        var NODE_JS = !root.JS_SHA3_NO_NODE_JS && typeof process === "object" && process.versions && process.versions.node;
        if (NODE_JS) {
            root = commonjsGlobal
        }
        var COMMON_JS = !root.JS_SHA3_NO_COMMON_JS && "object" === "object" && module.exports;
        var HEX_CHARS = "0123456789abcdef".split("");
        var SHAKE_PADDING = [31, 7936, 2031616, 520093696];
        var KECCAK_PADDING = [1, 256, 65536, 16777216];
        var PADDING = [6, 1536, 393216, 100663296];
        var SHIFT = [0, 8, 16, 24];
        var RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];
        var BITS = [224, 256, 384, 512];
        var SHAKE_BITS = [128, 256];
        var OUTPUT_TYPES = ["hex", "buffer", "arrayBuffer", "array"];
        var createOutputMethod = function (bits, padding, outputType) {
            return function (message) {
                return new Keccak(bits, padding, bits).update(message)[outputType]()
            }
        };
        var createShakeOutputMethod = function (bits, padding, outputType) {
            return function (message, outputBits) {
                return new Keccak(bits, padding, outputBits).update(message)[outputType]()
            }
        };
        var createMethod = function (bits, padding) {
            var method = createOutputMethod(bits, padding, "hex");
            method.create = function () {
                return new Keccak(bits, padding, bits)
            };
            method.update = function (message) {
                return method.create().update(message)
            };
            for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
                var type = OUTPUT_TYPES[i];
                method[type] = createOutputMethod(bits, padding, type)
            }
            return method
        };
        var createShakeMethod = function (bits, padding) {
            var method = createShakeOutputMethod(bits, padding, "hex");
            method.create = function (outputBits) {
                return new Keccak(bits, padding, outputBits)
            };
            method.update = function (message, outputBits) {
                return method.create(outputBits).update(message)
            };
            for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
                var type = OUTPUT_TYPES[i];
                method[type] = createShakeOutputMethod(bits, padding, type)
            }
            return method
        };
        var algorithms = [{
            name: "keccak",
            padding: KECCAK_PADDING,
            bits: BITS,
            createMethod: createMethod
        }, {
            name: "sha3",
            padding: PADDING,
            bits: BITS,
            createMethod: createMethod
        }, {
            name: "shake",
            padding: SHAKE_PADDING,
            bits: SHAKE_BITS,
            createMethod: createShakeMethod
        }];
        var methods = {},
            methodNames = [];
        for (var i = 0; i < algorithms.length; ++i) {
            var algorithm = algorithms[i];
            var bits = algorithm.bits;
            for (var j = 0; j < bits.length; ++j) {
                var methodName = algorithm.name + "_" + bits[j];
                methodNames.push(methodName);
                methods[methodName] = algorithm.createMethod(bits[j], algorithm.padding)
            }
        }

        function Keccak(bits, padding, outputBits) {
            this.blocks = [];
            this.s = [];
            this.padding = padding;
            this.outputBits = outputBits;
            this.reset = true;
            this.block = 0;
            this.start = 0;
            this.blockCount = 1600 - (bits << 1) >> 5;
            this.byteCount = this.blockCount << 2;
            this.outputBlocks = outputBits >> 5;
            this.extraBytes = (outputBits & 31) >> 3;
            for (var i = 0; i < 50; ++i) {
                this.s[i] = 0
            }
        }
        Keccak.prototype.update = function (message) {
            var notString = typeof message !== "string";
            if (notString && message.constructor === ArrayBuffer) {
                message = new Uint8Array(message)
            }
            var length = message.length,
                blocks = this.blocks,
                byteCount = this.byteCount,
                blockCount = this.blockCount,
                index = 0,
                s = this.s,
                i, code;
            while (index < length) {
                if (this.reset) {
                    this.reset = false;
                    blocks[0] = this.block;
                    for (i = 1; i < blockCount + 1; ++i) {
                        blocks[i] = 0
                    }
                }
                if (notString) {
                    for (i = this.start; index < length && i < byteCount; ++index) {
                        blocks[i >> 2] |= message[index] << SHIFT[i++ & 3]
                    }
                } else {
                    for (i = this.start; index < length && i < byteCount; ++index) {
                        code = message.charCodeAt(index);
                        if (code < 128) {
                            blocks[i >> 2] |= code << SHIFT[i++ & 3]
                        } else if (code < 2048) {
                            blocks[i >> 2] |= (192 | code >> 6) << SHIFT[i++ & 3];
                            blocks[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3]
                        } else if (code < 55296 || code >= 57344) {
                            blocks[i >> 2] |= (224 | code >> 12) << SHIFT[i++ & 3];
                            blocks[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[i++ & 3];
                            blocks[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3]
                        } else {
                            code = 65536 + ((code & 1023) << 10 | message.charCodeAt(++index) & 1023);
                            blocks[i >> 2] |= (240 | code >> 18) << SHIFT[i++ & 3];
                            blocks[i >> 2] |= (128 | code >> 12 & 63) << SHIFT[i++ & 3];
                            blocks[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[i++ & 3];
                            blocks[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3]
                        }
                    }
                }
                this.lastByteIndex = i;
                if (i >= byteCount) {
                    this.start = i - byteCount;
                    this.block = blocks[blockCount];
                    for (i = 0; i < blockCount; ++i) {
                        s[i] ^= blocks[i]
                    }
                    f(s);
                    this.reset = true
                } else {
                    this.start = i
                }
            }
            return this
        };
        Keccak.prototype.finalize = function () {
            var blocks = this.blocks,
                i = this.lastByteIndex,
                blockCount = this.blockCount,
                s = this.s;
            blocks[i >> 2] |= this.padding[i & 3];
            if (this.lastByteIndex === this.byteCount) {
                blocks[0] = blocks[blockCount];
                for (i = 1; i < blockCount + 1; ++i) {
                    blocks[i] = 0
                }
            }
            blocks[blockCount - 1] |= 2147483648;
            for (i = 0; i < blockCount; ++i) {
                s[i] ^= blocks[i]
            }
            f(s)
        };
        Keccak.prototype.toString = Keccak.prototype.hex = function () {
            this.finalize();
            var blockCount = this.blockCount,
                s = this.s,
                outputBlocks = this.outputBlocks,
                extraBytes = this.extraBytes,
                i = 0,
                j = 0;
            var hex = "",
                block;
            while (j < outputBlocks) {
                for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                    block = s[i];
                    hex += HEX_CHARS[block >> 4 & 15] + HEX_CHARS[block & 15] + HEX_CHARS[block >> 12 & 15] + HEX_CHARS[block >> 8 & 15] + HEX_CHARS[block >> 20 & 15] + HEX_CHARS[block >> 16 & 15] + HEX_CHARS[block >> 28 & 15] + HEX_CHARS[block >> 24 & 15]
                }
                if (j % blockCount === 0) {
                    f(s);
                    i = 0
                }
            }
            if (extraBytes) {
                block = s[i];
                if (extraBytes > 0) {
                    hex += HEX_CHARS[block >> 4 & 15] + HEX_CHARS[block & 15]
                }
                if (extraBytes > 1) {
                    hex += HEX_CHARS[block >> 12 & 15] + HEX_CHARS[block >> 8 & 15]
                }
                if (extraBytes > 2) {
                    hex += HEX_CHARS[block >> 20 & 15] + HEX_CHARS[block >> 16 & 15]
                }
            }
            return hex
        };
        Keccak.prototype.arrayBuffer = function () {
            this.finalize();
            var blockCount = this.blockCount,
                s = this.s,
                outputBlocks = this.outputBlocks,
                extraBytes = this.extraBytes,
                i = 0,
                j = 0;
            var bytes = this.outputBits >> 3;
            var buffer;
            if (extraBytes) {
                buffer = new ArrayBuffer(outputBlocks + 1 << 2)
            } else {
                buffer = new ArrayBuffer(bytes)
            }
            var array = new Uint32Array(buffer);
            while (j < outputBlocks) {
                for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                    array[j] = s[i]
                }
                if (j % blockCount === 0) {
                    f(s)
                }
            }
            if (extraBytes) {
                array[i] = s[i];
                buffer = buffer.slice(0, bytes)
            }
            return buffer
        };
        Keccak.prototype.buffer = Keccak.prototype.arrayBuffer;
        Keccak.prototype.digest = Keccak.prototype.array = function () {
            this.finalize();
            var blockCount = this.blockCount,
                s = this.s,
                outputBlocks = this.outputBlocks,
                extraBytes = this.extraBytes,
                i = 0,
                j = 0;
            var array = [],
                offset, block;
            while (j < outputBlocks) {
                for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                    offset = j << 2;
                    block = s[i];
                    array[offset] = block & 255;
                    array[offset + 1] = block >> 8 & 255;
                    array[offset + 2] = block >> 16 & 255;
                    array[offset + 3] = block >> 24 & 255
                }
                if (j % blockCount === 0) {
                    f(s)
                }
            }
            if (extraBytes) {
                offset = j << 2;
                block = s[i];
                if (extraBytes > 0) {
                    array[offset] = block & 255
                }
                if (extraBytes > 1) {
                    array[offset + 1] = block >> 8 & 255
                }
                if (extraBytes > 2) {
                    array[offset + 2] = block >> 16 & 255
                }
            }
            return array
        };
        var f = function (s) {
            var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33, b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
            for (n = 0; n < 48; n += 2) {
                c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
                c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
                c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
                c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
                c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
                c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
                c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
                c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
                c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
                c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];
                h = c8 ^ (c2 << 1 | c3 >>> 31);
                l = c9 ^ (c3 << 1 | c2 >>> 31);
                s[0] ^= h;
                s[1] ^= l;
                s[10] ^= h;
                s[11] ^= l;
                s[20] ^= h;
                s[21] ^= l;
                s[30] ^= h;
                s[31] ^= l;
                s[40] ^= h;
                s[41] ^= l;
                h = c0 ^ (c4 << 1 | c5 >>> 31);
                l = c1 ^ (c5 << 1 | c4 >>> 31);
                s[2] ^= h;
                s[3] ^= l;
                s[12] ^= h;
                s[13] ^= l;
                s[22] ^= h;
                s[23] ^= l;
                s[32] ^= h;
                s[33] ^= l;
                s[42] ^= h;
                s[43] ^= l;
                h = c2 ^ (c6 << 1 | c7 >>> 31);
                l = c3 ^ (c7 << 1 | c6 >>> 31);
                s[4] ^= h;
                s[5] ^= l;
                s[14] ^= h;
                s[15] ^= l;
                s[24] ^= h;
                s[25] ^= l;
                s[34] ^= h;
                s[35] ^= l;
                s[44] ^= h;
                s[45] ^= l;
                h = c4 ^ (c8 << 1 | c9 >>> 31);
                l = c5 ^ (c9 << 1 | c8 >>> 31);
                s[6] ^= h;
                s[7] ^= l;
                s[16] ^= h;
                s[17] ^= l;
                s[26] ^= h;
                s[27] ^= l;
                s[36] ^= h;
                s[37] ^= l;
                s[46] ^= h;
                s[47] ^= l;
                h = c6 ^ (c0 << 1 | c1 >>> 31);
                l = c7 ^ (c1 << 1 | c0 >>> 31);
                s[8] ^= h;
                s[9] ^= l;
                s[18] ^= h;
                s[19] ^= l;
                s[28] ^= h;
                s[29] ^= l;
                s[38] ^= h;
                s[39] ^= l;
                s[48] ^= h;
                s[49] ^= l;
                b0 = s[0];
                b1 = s[1];
                b32 = s[11] << 4 | s[10] >>> 28;
                b33 = s[10] << 4 | s[11] >>> 28;
                b14 = s[20] << 3 | s[21] >>> 29;
                b15 = s[21] << 3 | s[20] >>> 29;
                b46 = s[31] << 9 | s[30] >>> 23;
                b47 = s[30] << 9 | s[31] >>> 23;
                b28 = s[40] << 18 | s[41] >>> 14;
                b29 = s[41] << 18 | s[40] >>> 14;
                b20 = s[2] << 1 | s[3] >>> 31;
                b21 = s[3] << 1 | s[2] >>> 31;
                b2 = s[13] << 12 | s[12] >>> 20;
                b3 = s[12] << 12 | s[13] >>> 20;
                b34 = s[22] << 10 | s[23] >>> 22;
                b35 = s[23] << 10 | s[22] >>> 22;
                b16 = s[33] << 13 | s[32] >>> 19;
                b17 = s[32] << 13 | s[33] >>> 19;
                b48 = s[42] << 2 | s[43] >>> 30;
                b49 = s[43] << 2 | s[42] >>> 30;
                b40 = s[5] << 30 | s[4] >>> 2;
                b41 = s[4] << 30 | s[5] >>> 2;
                b22 = s[14] << 6 | s[15] >>> 26;
                b23 = s[15] << 6 | s[14] >>> 26;
                b4 = s[25] << 11 | s[24] >>> 21;
                b5 = s[24] << 11 | s[25] >>> 21;
                b36 = s[34] << 15 | s[35] >>> 17;
                b37 = s[35] << 15 | s[34] >>> 17;
                b18 = s[45] << 29 | s[44] >>> 3;
                b19 = s[44] << 29 | s[45] >>> 3;
                b10 = s[6] << 28 | s[7] >>> 4;
                b11 = s[7] << 28 | s[6] >>> 4;
                b42 = s[17] << 23 | s[16] >>> 9;
                b43 = s[16] << 23 | s[17] >>> 9;
                b24 = s[26] << 25 | s[27] >>> 7;
                b25 = s[27] << 25 | s[26] >>> 7;
                b6 = s[36] << 21 | s[37] >>> 11;
                b7 = s[37] << 21 | s[36] >>> 11;
                b38 = s[47] << 24 | s[46] >>> 8;
                b39 = s[46] << 24 | s[47] >>> 8;
                b30 = s[8] << 27 | s[9] >>> 5;
                b31 = s[9] << 27 | s[8] >>> 5;
                b12 = s[18] << 20 | s[19] >>> 12;
                b13 = s[19] << 20 | s[18] >>> 12;
                b44 = s[29] << 7 | s[28] >>> 25;
                b45 = s[28] << 7 | s[29] >>> 25;
                b26 = s[38] << 8 | s[39] >>> 24;
                b27 = s[39] << 8 | s[38] >>> 24;
                b8 = s[48] << 14 | s[49] >>> 18;
                b9 = s[49] << 14 | s[48] >>> 18;
                s[0] = b0 ^ ~b2 & b4;
                s[1] = b1 ^ ~b3 & b5;
                s[10] = b10 ^ ~b12 & b14;
                s[11] = b11 ^ ~b13 & b15;
                s[20] = b20 ^ ~b22 & b24;
                s[21] = b21 ^ ~b23 & b25;
                s[30] = b30 ^ ~b32 & b34;
                s[31] = b31 ^ ~b33 & b35;
                s[40] = b40 ^ ~b42 & b44;
                s[41] = b41 ^ ~b43 & b45;
                s[2] = b2 ^ ~b4 & b6;
                s[3] = b3 ^ ~b5 & b7;
                s[12] = b12 ^ ~b14 & b16;
                s[13] = b13 ^ ~b15 & b17;
                s[22] = b22 ^ ~b24 & b26;
                s[23] = b23 ^ ~b25 & b27;
                s[32] = b32 ^ ~b34 & b36;
                s[33] = b33 ^ ~b35 & b37;
                s[42] = b42 ^ ~b44 & b46;
                s[43] = b43 ^ ~b45 & b47;
                s[4] = b4 ^ ~b6 & b8;
                s[5] = b5 ^ ~b7 & b9;
                s[14] = b14 ^ ~b16 & b18;
                s[15] = b15 ^ ~b17 & b19;
                s[24] = b24 ^ ~b26 & b28;
                s[25] = b25 ^ ~b27 & b29;
                s[34] = b34 ^ ~b36 & b38;
                s[35] = b35 ^ ~b37 & b39;
                s[44] = b44 ^ ~b46 & b48;
                s[45] = b45 ^ ~b47 & b49;
                s[6] = b6 ^ ~b8 & b0;
                s[7] = b7 ^ ~b9 & b1;
                s[16] = b16 ^ ~b18 & b10;
                s[17] = b17 ^ ~b19 & b11;
                s[26] = b26 ^ ~b28 & b20;
                s[27] = b27 ^ ~b29 & b21;
                s[36] = b36 ^ ~b38 & b30;
                s[37] = b37 ^ ~b39 & b31;
                s[46] = b46 ^ ~b48 & b40;
                s[47] = b47 ^ ~b49 & b41;
                s[8] = b8 ^ ~b0 & b2;
                s[9] = b9 ^ ~b1 & b3;
                s[18] = b18 ^ ~b10 & b12;
                s[19] = b19 ^ ~b11 & b13;
                s[28] = b28 ^ ~b20 & b22;
                s[29] = b29 ^ ~b21 & b23;
                s[38] = b38 ^ ~b30 & b32;
                s[39] = b39 ^ ~b31 & b33;
                s[48] = b48 ^ ~b40 & b42;
                s[49] = b49 ^ ~b41 & b43;
                s[0] ^= RC[n];
                s[1] ^= RC[n + 1]
            }
        };
        if (COMMON_JS) {
            module.exports = methods
        } else {
            for (var i = 0; i < methodNames.length; ++i) {
                root[methodNames[i]] = methods[methodNames[i]]
            }
        }
    })()
});


var etherskeccak = createCommonjsModule(function (module, exports) {
    "use strict";
    var __importDefault = commonjsGlobal && commonjsGlobal.__importDefault || function (mod) {
        return mod && mod.__esModule ? mod : {
            default: mod
        }
    };
    Object.defineProperty(exports, "__esModule", {
        value: true
    });
    exports.keccak256 = void 0;
    var js_sha3_1 = __importDefault(sha3);

    function keccak256(data) {
        return "0x" + js_sha3_1.default.keccak_256(utils.arrayify(data))
    }
    exports.keccak256 = keccak256
});