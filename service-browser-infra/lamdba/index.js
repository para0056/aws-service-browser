"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb2, mod) => function __require() {
  return mod || (0, cb2[__getOwnPropNames(cb2)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@smithy/util-utf8/dist-es/fromUtf8.browser.js
var fromUtf8;
var init_fromUtf8_browser = __esm({
  "node_modules/@smithy/util-utf8/dist-es/fromUtf8.browser.js"() {
    fromUtf8 = (input) => new TextEncoder().encode(input);
  }
});

// node_modules/@smithy/util-utf8/dist-es/toUint8Array.js
var toUint8Array;
var init_toUint8Array = __esm({
  "node_modules/@smithy/util-utf8/dist-es/toUint8Array.js"() {
    init_fromUtf8_browser();
    toUint8Array = (data) => {
      if (typeof data === "string") {
        return fromUtf8(data);
      }
      if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
      }
      return new Uint8Array(data);
    };
  }
});

// node_modules/@smithy/util-utf8/dist-es/toUtf8.browser.js
var toUtf8;
var init_toUtf8_browser = __esm({
  "node_modules/@smithy/util-utf8/dist-es/toUtf8.browser.js"() {
    toUtf8 = (input) => {
      if (typeof input === "string") {
        return input;
      }
      if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
        throw new Error("@smithy/util-utf8: toUtf8 encoder function only accepts string | Uint8Array.");
      }
      return new TextDecoder("utf-8").decode(input);
    };
  }
});

// node_modules/@smithy/util-utf8/dist-es/index.js
var init_dist_es = __esm({
  "node_modules/@smithy/util-utf8/dist-es/index.js"() {
    init_fromUtf8_browser();
    init_toUint8Array();
    init_toUtf8_browser();
  }
});

// node_modules/node-fetch/browser.js
var require_browser = __commonJS({
  "node_modules/node-fetch/browser.js"(exports, module2) {
    "use strict";
    var getGlobal = function() {
      if (typeof self !== "undefined") {
        return self;
      }
      if (typeof window !== "undefined") {
        return window;
      }
      if (typeof global !== "undefined") {
        return global;
      }
      throw new Error("unable to locate global object");
    };
    var globalObject = getGlobal();
    module2.exports = exports = globalObject.fetch;
    if (globalObject.fetch) {
      exports.default = globalObject.fetch.bind(globalObject);
    }
    exports.Headers = globalObject.Headers;
    exports.Request = globalObject.Request;
    exports.Response = globalObject.Response;
  }
});

// lambda/lambda.ts
var lambda_exports = {};
__export(lambda_exports, {
  handler: () => handler
});
module.exports = __toCommonJS(lambda_exports);

// node_modules/@smithy/protocol-http/dist-es/extensions/httpExtensionConfiguration.js
var getHttpHandlerExtensionConfiguration = (runtimeConfig) => {
  return {
    setHttpHandler(handler2) {
      runtimeConfig.httpHandler = handler2;
    },
    httpHandler() {
      return runtimeConfig.httpHandler;
    },
    updateHttpClientConfig(key, value) {
      runtimeConfig.httpHandler?.updateHttpClientConfig(key, value);
    },
    httpHandlerConfigs() {
      return runtimeConfig.httpHandler.httpHandlerConfigs();
    }
  };
};
var resolveHttpHandlerRuntimeConfig = (httpHandlerExtensionConfiguration) => {
  return {
    httpHandler: httpHandlerExtensionConfiguration.httpHandler()
  };
};

// node_modules/@smithy/types/dist-es/endpoint.js
var EndpointURLScheme;
(function(EndpointURLScheme2) {
  EndpointURLScheme2["HTTP"] = "http";
  EndpointURLScheme2["HTTPS"] = "https";
})(EndpointURLScheme || (EndpointURLScheme = {}));

// node_modules/@smithy/types/dist-es/extensions/checksum.js
var AlgorithmId;
(function(AlgorithmId2) {
  AlgorithmId2["MD5"] = "md5";
  AlgorithmId2["CRC32"] = "crc32";
  AlgorithmId2["CRC32C"] = "crc32c";
  AlgorithmId2["SHA1"] = "sha1";
  AlgorithmId2["SHA256"] = "sha256";
})(AlgorithmId || (AlgorithmId = {}));

// node_modules/@smithy/types/dist-es/middleware.js
var SMITHY_CONTEXT_KEY = "__smithy_context";

// node_modules/@smithy/protocol-http/dist-es/httpRequest.js
var HttpRequest = class _HttpRequest {
  method;
  protocol;
  hostname;
  port;
  path;
  query;
  headers;
  username;
  password;
  fragment;
  body;
  constructor(options) {
    this.method = options.method || "GET";
    this.hostname = options.hostname || "localhost";
    this.port = options.port;
    this.query = options.query || {};
    this.headers = options.headers || {};
    this.body = options.body;
    this.protocol = options.protocol ? options.protocol.slice(-1) !== ":" ? `${options.protocol}:` : options.protocol : "https:";
    this.path = options.path ? options.path.charAt(0) !== "/" ? `/${options.path}` : options.path : "/";
    this.username = options.username;
    this.password = options.password;
    this.fragment = options.fragment;
  }
  static clone(request) {
    const cloned = new _HttpRequest({
      ...request,
      headers: { ...request.headers }
    });
    if (cloned.query) {
      cloned.query = cloneQuery(cloned.query);
    }
    return cloned;
  }
  static isInstance(request) {
    if (!request) {
      return false;
    }
    const req = request;
    return "method" in req && "protocol" in req && "hostname" in req && "path" in req && typeof req["query"] === "object" && typeof req["headers"] === "object";
  }
  clone() {
    return _HttpRequest.clone(this);
  }
};
function cloneQuery(query) {
  return Object.keys(query).reduce((carry, paramName) => {
    const param = query[paramName];
    return {
      ...carry,
      [paramName]: Array.isArray(param) ? [...param] : param
    };
  }, {});
}

// node_modules/@smithy/protocol-http/dist-es/httpResponse.js
var HttpResponse = class {
  statusCode;
  reason;
  headers;
  body;
  constructor(options) {
    this.statusCode = options.statusCode;
    this.reason = options.reason;
    this.headers = options.headers || {};
    this.body = options.body;
  }
  static isInstance(response) {
    if (!response)
      return false;
    const resp = response;
    return typeof resp.statusCode === "number" && typeof resp.headers === "object";
  }
};

// node_modules/@aws-sdk/middleware-expect-continue/dist-es/index.js
function addExpectContinueMiddleware(options) {
  return (next) => async (args) => {
    const { request } = args;
    if (options.expectContinueHeader !== false && HttpRequest.isInstance(request) && request.body && options.runtime === "node" && options.requestHandler?.constructor?.name !== "FetchHttpHandler") {
      let sendHeader = true;
      if (typeof options.expectContinueHeader === "number") {
        try {
          const bodyLength = Number(request.headers?.["content-length"]) ?? options.bodyLengthChecker?.(request.body) ?? Infinity;
          sendHeader = bodyLength >= options.expectContinueHeader;
        } catch (e2) {
        }
      } else {
        sendHeader = !!options.expectContinueHeader;
      }
      if (sendHeader) {
        request.headers.Expect = "100-continue";
      }
    }
    return next({
      ...args,
      request
    });
  };
}
var addExpectContinueMiddlewareOptions = {
  step: "build",
  tags: ["SET_EXPECT_HEADER", "EXPECT_HEADER"],
  name: "addExpectContinueMiddleware",
  override: true
};
var getAddExpectContinuePlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(addExpectContinueMiddleware(options), addExpectContinueMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/constants.js
var RequestChecksumCalculation = {
  WHEN_SUPPORTED: "WHEN_SUPPORTED",
  WHEN_REQUIRED: "WHEN_REQUIRED"
};
var DEFAULT_REQUEST_CHECKSUM_CALCULATION = RequestChecksumCalculation.WHEN_SUPPORTED;
var ResponseChecksumValidation = {
  WHEN_SUPPORTED: "WHEN_SUPPORTED",
  WHEN_REQUIRED: "WHEN_REQUIRED"
};
var DEFAULT_RESPONSE_CHECKSUM_VALIDATION = RequestChecksumCalculation.WHEN_SUPPORTED;
var ChecksumAlgorithm;
(function(ChecksumAlgorithm2) {
  ChecksumAlgorithm2["MD5"] = "MD5";
  ChecksumAlgorithm2["CRC32"] = "CRC32";
  ChecksumAlgorithm2["CRC32C"] = "CRC32C";
  ChecksumAlgorithm2["CRC64NVME"] = "CRC64NVME";
  ChecksumAlgorithm2["SHA1"] = "SHA1";
  ChecksumAlgorithm2["SHA256"] = "SHA256";
})(ChecksumAlgorithm || (ChecksumAlgorithm = {}));
var ChecksumLocation;
(function(ChecksumLocation2) {
  ChecksumLocation2["HEADER"] = "header";
  ChecksumLocation2["TRAILER"] = "trailer";
})(ChecksumLocation || (ChecksumLocation = {}));
var DEFAULT_CHECKSUM_ALGORITHM = ChecksumAlgorithm.CRC32;

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/crc64-nvme-crt-container.js
var crc64NvmeCrtContainer = {
  CrtCrc64Nvme: null
};

// node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
function setCredentialFeature(credentials, feature, value) {
  if (!credentials.$source) {
    credentials.$source = {};
  }
  credentials.$source[feature] = value;
  return credentials;
}

// node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
function setFeature(context, feature, value) {
  if (!context.__aws_sdk_context) {
    context.__aws_sdk_context = {
      features: {}
    };
  } else if (!context.__aws_sdk_context.features) {
    context.__aws_sdk_context.features = {};
  }
  context.__aws_sdk_context.features[feature] = value;
}

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js
var getDateHeader = (response) => HttpResponse.isInstance(response) ? response.headers?.date ?? response.headers?.Date : void 0;

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js
var getSkewCorrectedDate = (systemClockOffset) => new Date(Date.now() + systemClockOffset);

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js
var isClockSkewed = (clockTime, systemClockOffset) => Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >= 3e5;

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js
var getUpdatedSystemClockOffset = (clockTime, currentSystemClockOffset) => {
  const clockTimeInMs = Date.parse(clockTime);
  if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) {
    return clockTimeInMs - Date.now();
  }
  return currentSystemClockOffset;
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
var throwSigningPropertyError = (name, property) => {
  if (!property) {
    throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
  }
  return property;
};
var validateSigningProperties = async (signingProperties) => {
  const context = throwSigningPropertyError("context", signingProperties.context);
  const config = throwSigningPropertyError("config", signingProperties.config);
  const authScheme = context.endpointV2?.properties?.authSchemes?.[0];
  const signerFunction = throwSigningPropertyError("signer", config.signer);
  const signer = await signerFunction(authScheme);
  const signingRegion = signingProperties?.signingRegion;
  const signingRegionSet = signingProperties?.signingRegionSet;
  const signingName = signingProperties?.signingName;
  return {
    config,
    signer,
    signingRegion,
    signingRegionSet,
    signingName
  };
};
var AwsSdkSigV4Signer = class {
  async sign(httpRequest, identity, signingProperties) {
    if (!HttpRequest.isInstance(httpRequest)) {
      throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
    }
    const validatedProps = await validateSigningProperties(signingProperties);
    const { config, signer } = validatedProps;
    let { signingRegion, signingName } = validatedProps;
    const handlerExecutionContext = signingProperties.context;
    if (handlerExecutionContext?.authSchemes?.length ?? 0 > 1) {
      const [first, second] = handlerExecutionContext.authSchemes;
      if (first?.name === "sigv4a" && second?.name === "sigv4") {
        signingRegion = second?.signingRegion ?? signingRegion;
        signingName = second?.signingName ?? signingName;
      }
    }
    const signedRequest = await signer.sign(httpRequest, {
      signingDate: getSkewCorrectedDate(config.systemClockOffset),
      signingRegion,
      signingService: signingName
    });
    return signedRequest;
  }
  errorHandler(signingProperties) {
    return (error) => {
      const serverTime = error.ServerTime ?? getDateHeader(error.$response);
      if (serverTime) {
        const config = throwSigningPropertyError("config", signingProperties.config);
        const initialSystemClockOffset = config.systemClockOffset;
        config.systemClockOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset);
        const clockSkewCorrected = config.systemClockOffset !== initialSystemClockOffset;
        if (clockSkewCorrected && error.$metadata) {
          error.$metadata.clockSkewCorrected = true;
        }
      }
      throw error;
    };
  }
  successHandler(httpResponse, signingProperties) {
    const dateHeader = getDateHeader(httpResponse);
    if (dateHeader) {
      const config = throwSigningPropertyError("config", signingProperties.config);
      config.systemClockOffset = getUpdatedSystemClockOffset(dateHeader, config.systemClockOffset);
    }
  }
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4ASigner.js
var AwsSdkSigV4ASigner = class extends AwsSdkSigV4Signer {
  async sign(httpRequest, identity, signingProperties) {
    if (!HttpRequest.isInstance(httpRequest)) {
      throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
    }
    const { config, signer, signingRegion, signingRegionSet, signingName } = await validateSigningProperties(signingProperties);
    const configResolvedSigningRegionSet = await config.sigv4aSigningRegionSet?.();
    const multiRegionOverride = (configResolvedSigningRegionSet ?? signingRegionSet ?? [signingRegion]).join(",");
    const signedRequest = await signer.sign(httpRequest, {
      signingDate: getSkewCorrectedDate(config.systemClockOffset),
      signingRegion: multiRegionOverride,
      signingService: signingName
    });
    return signedRequest;
  }
};

// node_modules/@smithy/util-middleware/dist-es/getSmithyContext.js
var getSmithyContext = (context) => context[SMITHY_CONTEXT_KEY] || (context[SMITHY_CONTEXT_KEY] = {});

// node_modules/@smithy/util-middleware/dist-es/normalizeProvider.js
var normalizeProvider = (input) => {
  if (typeof input === "function")
    return input;
  const promisified = Promise.resolve(input);
  return () => promisified;
};

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js
var resolveAuthOptions = (candidateAuthOptions, authSchemePreference) => {
  if (!authSchemePreference || authSchemePreference.length === 0) {
    return candidateAuthOptions;
  }
  const preferredAuthOptions = [];
  for (const preferredSchemeName of authSchemePreference) {
    for (const candidateAuthOption of candidateAuthOptions) {
      const candidateAuthSchemeName = candidateAuthOption.schemeId.split("#")[1];
      if (candidateAuthSchemeName === preferredSchemeName) {
        preferredAuthOptions.push(candidateAuthOption);
      }
    }
  }
  for (const candidateAuthOption of candidateAuthOptions) {
    if (!preferredAuthOptions.find(({ schemeId }) => schemeId === candidateAuthOption.schemeId)) {
      preferredAuthOptions.push(candidateAuthOption);
    }
  }
  return preferredAuthOptions;
};

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
  const map2 = /* @__PURE__ */ new Map();
  for (const scheme of httpAuthSchemes) {
    map2.set(scheme.schemeId, scheme);
  }
  return map2;
}
var httpAuthSchemeMiddleware = (config, mwOptions) => (next, context) => async (args) => {
  const options = config.httpAuthSchemeProvider(await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input));
  const authSchemePreference = config.authSchemePreference ? await config.authSchemePreference() : [];
  const resolvedOptions = resolveAuthOptions(options, authSchemePreference);
  const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
  const smithyContext = getSmithyContext(context);
  const failureReasons = [];
  for (const option of resolvedOptions) {
    const scheme = authSchemes.get(option.schemeId);
    if (!scheme) {
      failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` was not enabled for this service.`);
      continue;
    }
    const identityProvider = scheme.identityProvider(await mwOptions.identityProviderConfigProvider(config));
    if (!identityProvider) {
      failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` did not have an IdentityProvider configured.`);
      continue;
    }
    const { identityProperties = {}, signingProperties = {} } = option.propertiesExtractor?.(config, context) || {};
    option.identityProperties = Object.assign(option.identityProperties || {}, identityProperties);
    option.signingProperties = Object.assign(option.signingProperties || {}, signingProperties);
    smithyContext.selectedHttpAuthScheme = {
      httpAuthOption: option,
      identity: await identityProvider(option.identityProperties),
      signer: scheme.signer
    };
    break;
  }
  if (!smithyContext.selectedHttpAuthScheme) {
    throw new Error(failureReasons.join("\n"));
  }
  return next(args);
};

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js
var httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
  step: "serialize",
  tags: ["HTTP_AUTH_SCHEME"],
  name: "httpAuthSchemeMiddleware",
  override: true,
  relation: "before",
  toMiddleware: "endpointV2Middleware"
};
var getHttpAuthSchemeEndpointRuleSetPlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
      httpAuthSchemeParametersProvider,
      identityProviderConfigProvider
    }), httpAuthSchemeEndpointRuleSetMiddlewareOptions);
  }
});

// node_modules/@smithy/middleware-serde/dist-es/deserializerMiddleware.js
var deserializerMiddleware = (options, deserializer) => (next, context) => async (args) => {
  const { response } = await next(args);
  try {
    const parsed = await deserializer(response, options);
    return {
      response,
      output: parsed
    };
  } catch (error) {
    Object.defineProperty(error, "$response", {
      value: response
    });
    if (!("$metadata" in error)) {
      const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
      try {
        error.message += "\n  " + hint;
      } catch (e2) {
        if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") {
          console.warn(hint);
        } else {
          context.logger?.warn?.(hint);
        }
      }
      if (typeof error.$responseBodyText !== "undefined") {
        if (error.$response) {
          error.$response.body = error.$responseBodyText;
        }
      }
      try {
        if (HttpResponse.isInstance(response)) {
          const { headers = {} } = response;
          const headerEntries = Object.entries(headers);
          error.$metadata = {
            httpStatusCode: response.statusCode,
            requestId: findHeader(/^x-[\w-]+-request-?id$/, headerEntries),
            extendedRequestId: findHeader(/^x-[\w-]+-id-2$/, headerEntries),
            cfId: findHeader(/^x-[\w-]+-cf-id$/, headerEntries)
          };
        }
      } catch (e2) {
      }
    }
    throw error;
  }
};
var findHeader = (pattern, headers) => {
  return (headers.find(([k2]) => {
    return k2.match(pattern);
  }) || [void 0, void 0])[1];
};

// node_modules/@smithy/middleware-serde/dist-es/serializerMiddleware.js
var serializerMiddleware = (options, serializer) => (next, context) => async (args) => {
  const endpointConfig = options;
  const endpoint = context.endpointV2?.url && endpointConfig.urlParser ? async () => endpointConfig.urlParser(context.endpointV2.url) : endpointConfig.endpoint;
  if (!endpoint) {
    throw new Error("No valid endpoint provider available.");
  }
  const request = await serializer(args.input, { ...options, endpoint });
  return next({
    ...args,
    request
  });
};

// node_modules/@smithy/middleware-serde/dist-es/serdePlugin.js
var deserializerMiddlewareOption = {
  name: "deserializerMiddleware",
  step: "deserialize",
  tags: ["DESERIALIZER"],
  override: true
};
var serializerMiddlewareOption = {
  name: "serializerMiddleware",
  step: "serialize",
  tags: ["SERIALIZER"],
  override: true
};
function getSerdePlugin(config, serializer, deserializer) {
  return {
    applyToStack: (commandStack) => {
      commandStack.add(deserializerMiddleware(config, deserializer), deserializerMiddlewareOption);
      commandStack.add(serializerMiddleware(config, serializer), serializerMiddlewareOption);
    }
  };
}

// node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js
var defaultErrorHandler = (signingProperties) => (error) => {
  throw error;
};
var defaultSuccessHandler = (httpResponse, signingProperties) => {
};
var httpSigningMiddleware = (config) => (next, context) => async (args) => {
  if (!HttpRequest.isInstance(args.request)) {
    return next(args);
  }
  const smithyContext = getSmithyContext(context);
  const scheme = smithyContext.selectedHttpAuthScheme;
  if (!scheme) {
    throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
  }
  const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
  const output = await next({
    ...args,
    request: await signer.sign(args.request, identity, signingProperties)
  }).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
  (signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
  return output;
};

// node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js
var httpSigningMiddlewareOptions = {
  step: "finalizeRequest",
  tags: ["HTTP_SIGNING"],
  name: "httpSigningMiddleware",
  aliases: ["apiKeyMiddleware", "tokenMiddleware", "awsAuthMiddleware"],
  override: true,
  relation: "after",
  toMiddleware: "retryMiddleware"
};
var getHttpSigningPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(httpSigningMiddleware(config), httpSigningMiddlewareOptions);
  }
});

// node_modules/@smithy/core/dist-es/normalizeProvider.js
var normalizeProvider2 = (input) => {
  if (typeof input === "function")
    return input;
  const promisified = Promise.resolve(input);
  return () => promisified;
};

// node_modules/@smithy/util-base64/dist-es/constants.browser.js
var chars = `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`;
var alphabetByEncoding = Object.entries(chars).reduce((acc, [i2, c2]) => {
  acc[c2] = Number(i2);
  return acc;
}, {});
var alphabetByValue = chars.split("");
var bitsPerLetter = 6;
var bitsPerByte = 8;
var maxLetterValue = 63;

// node_modules/@smithy/util-base64/dist-es/fromBase64.browser.js
var fromBase64 = (input) => {
  let totalByteLength = input.length / 4 * 3;
  if (input.slice(-2) === "==") {
    totalByteLength -= 2;
  } else if (input.slice(-1) === "=") {
    totalByteLength--;
  }
  const out = new ArrayBuffer(totalByteLength);
  const dataView = new DataView(out);
  for (let i2 = 0; i2 < input.length; i2 += 4) {
    let bits = 0;
    let bitLength = 0;
    for (let j2 = i2, limit = i2 + 3; j2 <= limit; j2++) {
      if (input[j2] !== "=") {
        if (!(input[j2] in alphabetByEncoding)) {
          throw new TypeError(`Invalid character ${input[j2]} in base64 string.`);
        }
        bits |= alphabetByEncoding[input[j2]] << (limit - j2) * bitsPerLetter;
        bitLength += bitsPerLetter;
      } else {
        bits >>= bitsPerLetter;
      }
    }
    const chunkOffset = i2 / 4 * 3;
    bits >>= bitLength % bitsPerByte;
    const byteLength = Math.floor(bitLength / bitsPerByte);
    for (let k2 = 0; k2 < byteLength; k2++) {
      const offset = (byteLength - k2 - 1) * bitsPerByte;
      dataView.setUint8(chunkOffset + k2, (bits & 255 << offset) >> offset);
    }
  }
  return new Uint8Array(out);
};

// node_modules/@smithy/util-base64/dist-es/toBase64.browser.js
init_dist_es();
function toBase64(_input) {
  let input;
  if (typeof _input === "string") {
    input = fromUtf8(_input);
  } else {
    input = _input;
  }
  const isArrayLike = typeof input === "object" && typeof input.length === "number";
  const isUint8Array = typeof input === "object" && typeof input.byteOffset === "number" && typeof input.byteLength === "number";
  if (!isArrayLike && !isUint8Array) {
    throw new Error("@smithy/util-base64: toBase64 encoder function only accepts string | Uint8Array.");
  }
  let str = "";
  for (let i2 = 0; i2 < input.length; i2 += 3) {
    let bits = 0;
    let bitLength = 0;
    for (let j2 = i2, limit = Math.min(i2 + 3, input.length); j2 < limit; j2++) {
      bits |= input[j2] << (limit - j2 - 1) * bitsPerByte;
      bitLength += bitsPerByte;
    }
    const bitClusterCount = Math.ceil(bitLength / bitsPerLetter);
    bits <<= bitClusterCount * bitsPerLetter - bitLength;
    for (let k2 = 1; k2 <= bitClusterCount; k2++) {
      const offset = (bitClusterCount - k2) * bitsPerLetter;
      str += alphabetByValue[(bits & maxLetterValue << offset) >> offset];
    }
    str += "==".slice(0, 4 - bitClusterCount);
  }
  return str;
}

// node_modules/@smithy/util-stream/dist-es/blob/Uint8ArrayBlobAdapter.js
init_dist_es();
var Uint8ArrayBlobAdapter = class _Uint8ArrayBlobAdapter extends Uint8Array {
  static fromString(source, encoding = "utf-8") {
    if (typeof source === "string") {
      if (encoding === "base64") {
        return _Uint8ArrayBlobAdapter.mutate(fromBase64(source));
      }
      return _Uint8ArrayBlobAdapter.mutate(fromUtf8(source));
    }
    throw new Error(`Unsupported conversion from ${typeof source} to Uint8ArrayBlobAdapter.`);
  }
  static mutate(source) {
    Object.setPrototypeOf(source, _Uint8ArrayBlobAdapter.prototype);
    return source;
  }
  transformToString(encoding = "utf-8") {
    if (encoding === "base64") {
      return toBase64(this);
    }
    return toUtf8(this);
  }
};

// node_modules/@smithy/util-stream/dist-es/checksum/ChecksumStream.browser.js
var ReadableStreamRef = typeof ReadableStream === "function" ? ReadableStream : function() {
};
var ChecksumStream = class extends ReadableStreamRef {
};

// node_modules/@smithy/util-stream/dist-es/stream-type-check.js
var isReadableStream = (stream) => typeof ReadableStream === "function" && (stream?.constructor?.name === ReadableStream.name || stream instanceof ReadableStream);

// node_modules/@smithy/util-stream/dist-es/checksum/createChecksumStream.browser.js
var createChecksumStream = ({ expectedChecksum, checksum, source, checksumSourceLocation, base64Encoder }) => {
  if (!isReadableStream(source)) {
    throw new Error(`@smithy/util-stream: unsupported source type ${source?.constructor?.name ?? source} in ChecksumStream.`);
  }
  const encoder = base64Encoder ?? toBase64;
  if (typeof TransformStream !== "function") {
    throw new Error("@smithy/util-stream: unable to instantiate ChecksumStream because API unavailable: ReadableStream/TransformStream.");
  }
  const transform = new TransformStream({
    start() {
    },
    async transform(chunk, controller) {
      checksum.update(chunk);
      controller.enqueue(chunk);
    },
    async flush(controller) {
      const digest = await checksum.digest();
      const received = encoder(digest);
      if (expectedChecksum !== received) {
        const error = new Error(`Checksum mismatch: expected "${expectedChecksum}" but received "${received}" in response header "${checksumSourceLocation}".`);
        controller.error(error);
      } else {
        controller.terminate();
      }
    }
  });
  source.pipeThrough(transform);
  const readable = transform.readable;
  Object.setPrototypeOf(readable, ChecksumStream.prototype);
  return readable;
};

// node_modules/@smithy/util-stream/dist-es/ByteArrayCollector.js
var ByteArrayCollector = class {
  allocByteArray;
  byteLength = 0;
  byteArrays = [];
  constructor(allocByteArray) {
    this.allocByteArray = allocByteArray;
  }
  push(byteArray) {
    this.byteArrays.push(byteArray);
    this.byteLength += byteArray.byteLength;
  }
  flush() {
    if (this.byteArrays.length === 1) {
      const bytes = this.byteArrays[0];
      this.reset();
      return bytes;
    }
    const aggregation = this.allocByteArray(this.byteLength);
    let cursor = 0;
    for (let i2 = 0; i2 < this.byteArrays.length; ++i2) {
      const bytes = this.byteArrays[i2];
      aggregation.set(bytes, cursor);
      cursor += bytes.byteLength;
    }
    this.reset();
    return aggregation;
  }
  reset() {
    this.byteArrays = [];
    this.byteLength = 0;
  }
};

// node_modules/@smithy/util-stream/dist-es/createBufferedReadableStream.js
function createBufferedReadableStream(upstream, size, logger2) {
  const reader = upstream.getReader();
  let streamBufferingLoggedWarning = false;
  let bytesSeen = 0;
  const buffers = ["", new ByteArrayCollector((size2) => new Uint8Array(size2))];
  let mode = -1;
  const pull = async (controller) => {
    const { value, done } = await reader.read();
    const chunk = value;
    if (done) {
      if (mode !== -1) {
        const remainder = flush(buffers, mode);
        if (sizeOf(remainder) > 0) {
          controller.enqueue(remainder);
        }
      }
      controller.close();
    } else {
      const chunkMode = modeOf(chunk, false);
      if (mode !== chunkMode) {
        if (mode >= 0) {
          controller.enqueue(flush(buffers, mode));
        }
        mode = chunkMode;
      }
      if (mode === -1) {
        controller.enqueue(chunk);
        return;
      }
      const chunkSize = sizeOf(chunk);
      bytesSeen += chunkSize;
      const bufferSize = sizeOf(buffers[mode]);
      if (chunkSize >= size && bufferSize === 0) {
        controller.enqueue(chunk);
      } else {
        const newSize = merge(buffers, mode, chunk);
        if (!streamBufferingLoggedWarning && bytesSeen > size * 2) {
          streamBufferingLoggedWarning = true;
          logger2?.warn(`@smithy/util-stream - stream chunk size ${chunkSize} is below threshold of ${size}, automatically buffering.`);
        }
        if (newSize >= size) {
          controller.enqueue(flush(buffers, mode));
        } else {
          await pull(controller);
        }
      }
    }
  };
  return new ReadableStream({
    pull
  });
}
var createBufferedReadable = createBufferedReadableStream;
function merge(buffers, mode, chunk) {
  switch (mode) {
    case 0:
      buffers[0] += chunk;
      return sizeOf(buffers[0]);
    case 1:
    case 2:
      buffers[mode].push(chunk);
      return sizeOf(buffers[mode]);
  }
}
function flush(buffers, mode) {
  switch (mode) {
    case 0:
      const s2 = buffers[0];
      buffers[0] = "";
      return s2;
    case 1:
    case 2:
      return buffers[mode].flush();
  }
  throw new Error(`@smithy/util-stream - invalid index ${mode} given to flush()`);
}
function sizeOf(chunk) {
  return chunk?.byteLength ?? chunk?.length ?? 0;
}
function modeOf(chunk, allowBuffer = true) {
  if (allowBuffer && typeof Buffer !== "undefined" && chunk instanceof Buffer) {
    return 2;
  }
  if (chunk instanceof Uint8Array) {
    return 1;
  }
  if (typeof chunk === "string") {
    return 0;
  }
  return -1;
}

// node_modules/@smithy/util-stream/dist-es/getAwsChunkedEncodingStream.browser.js
var getAwsChunkedEncodingStream = (readableStream, options) => {
  const { base64Encoder, bodyLengthChecker, checksumAlgorithmFn, checksumLocationName, streamHasher } = options;
  const checksumRequired = base64Encoder !== void 0 && bodyLengthChecker !== void 0 && checksumAlgorithmFn !== void 0 && checksumLocationName !== void 0 && streamHasher !== void 0;
  const digest = checksumRequired ? streamHasher(checksumAlgorithmFn, readableStream) : void 0;
  const reader = readableStream.getReader();
  return new ReadableStream({
    async pull(controller) {
      const { value, done } = await reader.read();
      if (done) {
        controller.enqueue(`0\r
`);
        if (checksumRequired) {
          const checksum = base64Encoder(await digest);
          controller.enqueue(`${checksumLocationName}:${checksum}\r
`);
          controller.enqueue(`\r
`);
        }
        controller.close();
      } else {
        controller.enqueue(`${(bodyLengthChecker(value) || 0).toString(16)}\r
${value}\r
`);
      }
    }
  });
};

// node_modules/@smithy/util-stream/dist-es/headStream.browser.js
async function headStream(stream, bytes) {
  let byteLengthCounter = 0;
  const chunks = [];
  const reader = stream.getReader();
  let isDone = false;
  while (!isDone) {
    const { done, value } = await reader.read();
    if (value) {
      chunks.push(value);
      byteLengthCounter += value?.byteLength ?? 0;
    }
    if (byteLengthCounter >= bytes) {
      break;
    }
    isDone = done;
  }
  reader.releaseLock();
  const collected = new Uint8Array(Math.min(bytes, byteLengthCounter));
  let offset = 0;
  for (const chunk of chunks) {
    if (chunk.byteLength > collected.byteLength - offset) {
      collected.set(chunk.subarray(0, collected.byteLength - offset), offset);
      break;
    } else {
      collected.set(chunk, offset);
    }
    offset += chunk.length;
  }
  return collected;
}

// node_modules/@smithy/util-uri-escape/dist-es/escape-uri.js
var escapeUri = (uri) => encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode);
var hexEncode = (c2) => `%${c2.charCodeAt(0).toString(16).toUpperCase()}`;

// node_modules/@smithy/querystring-builder/dist-es/index.js
function buildQueryString(query) {
  const parts = [];
  for (let key of Object.keys(query).sort()) {
    const value = query[key];
    key = escapeUri(key);
    if (Array.isArray(value)) {
      for (let i2 = 0, iLen = value.length; i2 < iLen; i2++) {
        parts.push(`${key}=${escapeUri(value[i2])}`);
      }
    } else {
      let qsEntry = key;
      if (value || typeof value === "string") {
        qsEntry += `=${escapeUri(value)}`;
      }
      parts.push(qsEntry);
    }
  }
  return parts.join("&");
}

// node_modules/@smithy/fetch-http-handler/dist-es/create-request.js
function createRequest(url, requestOptions) {
  return new Request(url, requestOptions);
}

// node_modules/@smithy/fetch-http-handler/dist-es/request-timeout.js
function requestTimeout(timeoutInMs = 0) {
  return new Promise((resolve, reject) => {
    if (timeoutInMs) {
      setTimeout(() => {
        const timeoutError = new Error(`Request did not complete within ${timeoutInMs} ms`);
        timeoutError.name = "TimeoutError";
        reject(timeoutError);
      }, timeoutInMs);
    }
  });
}

// node_modules/@smithy/fetch-http-handler/dist-es/fetch-http-handler.js
var keepAliveSupport = {
  supported: void 0
};
var FetchHttpHandler = class _FetchHttpHandler {
  config;
  configProvider;
  static create(instanceOrOptions) {
    if (typeof instanceOrOptions?.handle === "function") {
      return instanceOrOptions;
    }
    return new _FetchHttpHandler(instanceOrOptions);
  }
  constructor(options) {
    if (typeof options === "function") {
      this.configProvider = options().then((opts) => opts || {});
    } else {
      this.config = options ?? {};
      this.configProvider = Promise.resolve(this.config);
    }
    if (keepAliveSupport.supported === void 0) {
      keepAliveSupport.supported = Boolean(typeof Request !== "undefined" && "keepalive" in createRequest("https://[::1]"));
    }
  }
  destroy() {
  }
  async handle(request, { abortSignal, requestTimeout: requestTimeout2 } = {}) {
    if (!this.config) {
      this.config = await this.configProvider;
    }
    const requestTimeoutInMs = requestTimeout2 ?? this.config.requestTimeout;
    const keepAlive = this.config.keepAlive === true;
    const credentials = this.config.credentials;
    if (abortSignal?.aborted) {
      const abortError = new Error("Request aborted");
      abortError.name = "AbortError";
      return Promise.reject(abortError);
    }
    let path = request.path;
    const queryString = buildQueryString(request.query || {});
    if (queryString) {
      path += `?${queryString}`;
    }
    if (request.fragment) {
      path += `#${request.fragment}`;
    }
    let auth = "";
    if (request.username != null || request.password != null) {
      const username = request.username ?? "";
      const password = request.password ?? "";
      auth = `${username}:${password}@`;
    }
    const { port, method } = request;
    const url = `${request.protocol}//${auth}${request.hostname}${port ? `:${port}` : ""}${path}`;
    const body = method === "GET" || method === "HEAD" ? void 0 : request.body;
    const requestOptions = {
      body,
      headers: new Headers(request.headers),
      method,
      credentials
    };
    if (this.config?.cache) {
      requestOptions.cache = this.config.cache;
    }
    if (body) {
      requestOptions.duplex = "half";
    }
    if (typeof AbortController !== "undefined") {
      requestOptions.signal = abortSignal;
    }
    if (keepAliveSupport.supported) {
      requestOptions.keepalive = keepAlive;
    }
    if (typeof this.config.requestInit === "function") {
      Object.assign(requestOptions, this.config.requestInit(request));
    }
    let removeSignalEventListener = () => {
    };
    const fetchRequest = createRequest(url, requestOptions);
    const raceOfPromises = [
      fetch(fetchRequest).then((response) => {
        const fetchHeaders = response.headers;
        const transformedHeaders = {};
        for (const pair of fetchHeaders.entries()) {
          transformedHeaders[pair[0]] = pair[1];
        }
        const hasReadableStream = response.body != void 0;
        if (!hasReadableStream) {
          return response.blob().then((body2) => ({
            response: new HttpResponse({
              headers: transformedHeaders,
              reason: response.statusText,
              statusCode: response.status,
              body: body2
            })
          }));
        }
        return {
          response: new HttpResponse({
            headers: transformedHeaders,
            reason: response.statusText,
            statusCode: response.status,
            body: response.body
          })
        };
      }),
      requestTimeout(requestTimeoutInMs)
    ];
    if (abortSignal) {
      raceOfPromises.push(new Promise((resolve, reject) => {
        const onAbort = () => {
          const abortError = new Error("Request aborted");
          abortError.name = "AbortError";
          reject(abortError);
        };
        if (typeof abortSignal.addEventListener === "function") {
          const signal = abortSignal;
          signal.addEventListener("abort", onAbort, { once: true });
          removeSignalEventListener = () => signal.removeEventListener("abort", onAbort);
        } else {
          abortSignal.onabort = onAbort;
        }
      }));
    }
    return Promise.race(raceOfPromises).finally(removeSignalEventListener);
  }
  updateHttpClientConfig(key, value) {
    this.config = void 0;
    this.configProvider = this.configProvider.then((config) => {
      config[key] = value;
      return config;
    });
  }
  httpHandlerConfigs() {
    return this.config ?? {};
  }
};

// node_modules/@smithy/fetch-http-handler/dist-es/stream-collector.js
var streamCollector = async (stream) => {
  if (typeof Blob === "function" && stream instanceof Blob || stream.constructor?.name === "Blob") {
    if (Blob.prototype.arrayBuffer !== void 0) {
      return new Uint8Array(await stream.arrayBuffer());
    }
    return collectBlob(stream);
  }
  return collectStream(stream);
};
async function collectBlob(blob) {
  const base64 = await readToBase64(blob);
  const arrayBuffer = fromBase64(base64);
  return new Uint8Array(arrayBuffer);
}
async function collectStream(stream) {
  const chunks = [];
  const reader = stream.getReader();
  let isDone = false;
  let length = 0;
  while (!isDone) {
    const { done, value } = await reader.read();
    if (value) {
      chunks.push(value);
      length += value.length;
    }
    isDone = done;
  }
  const collected = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    collected.set(chunk, offset);
    offset += chunk.length;
  }
  return collected;
}
function readToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      if (reader.readyState !== 2) {
        return reject(new Error("Reader aborted too early"));
      }
      const result = reader.result ?? "";
      const commaIndex = result.indexOf(",");
      const dataOffset = commaIndex > -1 ? commaIndex + 1 : result.length;
      resolve(result.substring(dataOffset));
    };
    reader.onabort = () => reject(new Error("Read aborted"));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

// node_modules/@smithy/util-hex-encoding/dist-es/index.js
var SHORT_TO_HEX = {};
var HEX_TO_SHORT = {};
for (let i2 = 0; i2 < 256; i2++) {
  let encodedByte = i2.toString(16).toLowerCase();
  if (encodedByte.length === 1) {
    encodedByte = `0${encodedByte}`;
  }
  SHORT_TO_HEX[i2] = encodedByte;
  HEX_TO_SHORT[encodedByte] = i2;
}
function fromHex(encoded) {
  if (encoded.length % 2 !== 0) {
    throw new Error("Hex encoded strings must have an even number length");
  }
  const out = new Uint8Array(encoded.length / 2);
  for (let i2 = 0; i2 < encoded.length; i2 += 2) {
    const encodedByte = encoded.slice(i2, i2 + 2).toLowerCase();
    if (encodedByte in HEX_TO_SHORT) {
      out[i2 / 2] = HEX_TO_SHORT[encodedByte];
    } else {
      throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
    }
  }
  return out;
}
function toHex(bytes) {
  let out = "";
  for (let i2 = 0; i2 < bytes.byteLength; i2++) {
    out += SHORT_TO_HEX[bytes[i2]];
  }
  return out;
}

// node_modules/@smithy/util-stream/dist-es/sdk-stream-mixin.browser.js
init_dist_es();
var ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
var sdkStreamMixin = (stream) => {
  if (!isBlobInstance(stream) && !isReadableStream(stream)) {
    const name = stream?.__proto__?.constructor?.name || stream;
    throw new Error(`Unexpected stream implementation, expect Blob or ReadableStream, got ${name}`);
  }
  let transformed = false;
  const transformToByteArray = async () => {
    if (transformed) {
      throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
    }
    transformed = true;
    return await streamCollector(stream);
  };
  const blobToWebStream = (blob) => {
    if (typeof blob.stream !== "function") {
      throw new Error("Cannot transform payload Blob to web stream. Please make sure the Blob.stream() is polyfilled.\nIf you are using React Native, this API is not yet supported, see: https://react-native.canny.io/feature-requests/p/fetch-streaming-body");
    }
    return blob.stream();
  };
  return Object.assign(stream, {
    transformToByteArray,
    transformToString: async (encoding) => {
      const buf = await transformToByteArray();
      if (encoding === "base64") {
        return toBase64(buf);
      } else if (encoding === "hex") {
        return toHex(buf);
      } else if (encoding === void 0 || encoding === "utf8" || encoding === "utf-8") {
        return toUtf8(buf);
      } else if (typeof TextDecoder === "function") {
        return new TextDecoder(encoding).decode(buf);
      } else {
        throw new Error("TextDecoder is not available, please make sure polyfill is provided.");
      }
    },
    transformToWebStream: () => {
      if (transformed) {
        throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
      }
      transformed = true;
      if (isBlobInstance(stream)) {
        return blobToWebStream(stream);
      } else if (isReadableStream(stream)) {
        return stream;
      } else {
        throw new Error(`Cannot transform payload to web stream, got ${stream}`);
      }
    }
  });
};
var isBlobInstance = (stream) => typeof Blob === "function" && stream instanceof Blob;

// node_modules/@smithy/util-stream/dist-es/splitStream.browser.js
async function splitStream(stream) {
  if (typeof stream.stream === "function") {
    stream = stream.stream();
  }
  const readableStream = stream;
  return readableStream.tee();
}

// node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js
var collectBody = async (streamBody = new Uint8Array(), context) => {
  if (streamBody instanceof Uint8Array) {
    return Uint8ArrayBlobAdapter.mutate(streamBody);
  }
  if (!streamBody) {
    return Uint8ArrayBlobAdapter.mutate(new Uint8Array());
  }
  const fromContext = context.streamCollector(streamBody);
  return Uint8ArrayBlobAdapter.mutate(await fromContext);
};

// node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js
function extendedEncodeURIComponent(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, function(c2) {
    return "%" + c2.charCodeAt(0).toString(16).toUpperCase();
  });
}

// node_modules/@smithy/core/dist-es/submodules/schema/deref.js
var deref = (schemaRef) => {
  if (typeof schemaRef === "function") {
    return schemaRef();
  }
  return schemaRef;
};

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js
function translateTraits(indicator) {
  if (typeof indicator === "object") {
    return indicator;
  }
  indicator = indicator | 0;
  const traits = {};
  let i2 = 0;
  for (const trait of [
    "httpLabel",
    "idempotent",
    "idempotencyToken",
    "sensitive",
    "httpPayload",
    "httpResponseCode",
    "httpQueryParams"
  ]) {
    if ((indicator >> i2++ & 1) === 1) {
      traits[trait] = 1;
    }
  }
  return traits;
}

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js
var NormalizedSchema = class _NormalizedSchema {
  ref;
  memberName;
  static symbol = Symbol.for("@smithy/nor");
  symbol = _NormalizedSchema.symbol;
  name;
  schema;
  _isMemberSchema;
  traits;
  memberTraits;
  normalizedTraits;
  constructor(ref, memberName) {
    this.ref = ref;
    this.memberName = memberName;
    const traitStack = [];
    let _ref = ref;
    let schema = ref;
    this._isMemberSchema = false;
    while (isMemberSchema(_ref)) {
      traitStack.push(_ref[1]);
      _ref = _ref[0];
      schema = deref(_ref);
      this._isMemberSchema = true;
    }
    if (traitStack.length > 0) {
      this.memberTraits = {};
      for (let i2 = traitStack.length - 1; i2 >= 0; --i2) {
        const traitSet = traitStack[i2];
        Object.assign(this.memberTraits, translateTraits(traitSet));
      }
    } else {
      this.memberTraits = 0;
    }
    if (schema instanceof _NormalizedSchema) {
      const computedMemberTraits = this.memberTraits;
      Object.assign(this, schema);
      this.memberTraits = Object.assign({}, computedMemberTraits, schema.getMemberTraits(), this.getMemberTraits());
      this.normalizedTraits = void 0;
      this.memberName = memberName ?? schema.memberName;
      return;
    }
    this.schema = deref(schema);
    if (isStaticSchema(this.schema)) {
      this.name = `${this.schema[1]}#${this.schema[2]}`;
      this.traits = this.schema[3];
    } else {
      this.name = this.memberName ?? String(schema);
      this.traits = 0;
    }
    if (this._isMemberSchema && !memberName) {
      throw new Error(`@smithy/core/schema - NormalizedSchema member init ${this.getName(true)} missing member name.`);
    }
  }
  static [Symbol.hasInstance](lhs) {
    const isPrototype = this.prototype.isPrototypeOf(lhs);
    if (!isPrototype && typeof lhs === "object" && lhs !== null) {
      const ns = lhs;
      return ns.symbol === this.symbol;
    }
    return isPrototype;
  }
  static of(ref) {
    const sc = deref(ref);
    if (sc instanceof _NormalizedSchema) {
      return sc;
    }
    if (isMemberSchema(sc)) {
      const [ns, traits] = sc;
      if (ns instanceof _NormalizedSchema) {
        Object.assign(ns.getMergedTraits(), translateTraits(traits));
        return ns;
      }
      throw new Error(`@smithy/core/schema - may not init unwrapped member schema=${JSON.stringify(ref, null, 2)}.`);
    }
    return new _NormalizedSchema(sc);
  }
  getSchema() {
    const sc = this.schema;
    if (sc[0] === 0) {
      return sc[4];
    }
    return sc;
  }
  getName(withNamespace = false) {
    const { name } = this;
    const short = !withNamespace && name && name.includes("#");
    return short ? name.split("#")[1] : name || void 0;
  }
  getMemberName() {
    return this.memberName;
  }
  isMemberSchema() {
    return this._isMemberSchema;
  }
  isListSchema() {
    const sc = this.getSchema();
    return typeof sc === "number" ? sc >= 64 && sc < 128 : sc[0] === 1;
  }
  isMapSchema() {
    const sc = this.getSchema();
    return typeof sc === "number" ? sc >= 128 && sc <= 255 : sc[0] === 2;
  }
  isStructSchema() {
    const sc = this.getSchema();
    return sc[0] === 3 || sc[0] === -3;
  }
  isBlobSchema() {
    const sc = this.getSchema();
    return sc === 21 || sc === 42;
  }
  isTimestampSchema() {
    const sc = this.getSchema();
    return typeof sc === "number" && sc >= 4 && sc <= 7;
  }
  isUnitSchema() {
    return this.getSchema() === "unit";
  }
  isDocumentSchema() {
    return this.getSchema() === 15;
  }
  isStringSchema() {
    return this.getSchema() === 0;
  }
  isBooleanSchema() {
    return this.getSchema() === 2;
  }
  isNumericSchema() {
    return this.getSchema() === 1;
  }
  isBigIntegerSchema() {
    return this.getSchema() === 17;
  }
  isBigDecimalSchema() {
    return this.getSchema() === 19;
  }
  isStreaming() {
    const { streaming } = this.getMergedTraits();
    return !!streaming || this.getSchema() === 42;
  }
  isIdempotencyToken() {
    const match = (traits2) => (traits2 & 4) === 4 || !!traits2?.idempotencyToken;
    const { normalizedTraits, traits, memberTraits } = this;
    return match(normalizedTraits) || match(traits) || match(memberTraits);
  }
  getMergedTraits() {
    return this.normalizedTraits ?? (this.normalizedTraits = {
      ...this.getOwnTraits(),
      ...this.getMemberTraits()
    });
  }
  getMemberTraits() {
    return translateTraits(this.memberTraits);
  }
  getOwnTraits() {
    return translateTraits(this.traits);
  }
  getKeySchema() {
    const [isDoc, isMap] = [this.isDocumentSchema(), this.isMapSchema()];
    if (!isDoc && !isMap) {
      throw new Error(`@smithy/core/schema - cannot get key for non-map: ${this.getName(true)}`);
    }
    const schema = this.getSchema();
    const memberSchema = isDoc ? 15 : schema[4] ?? 0;
    return member([memberSchema, 0], "key");
  }
  getValueSchema() {
    const sc = this.getSchema();
    const [isDoc, isMap, isList] = [this.isDocumentSchema(), this.isMapSchema(), this.isListSchema()];
    const memberSchema = typeof sc === "number" ? 63 & sc : sc && typeof sc === "object" && (isMap || isList) ? sc[3 + sc[0]] : isDoc ? 15 : void 0;
    if (memberSchema != null) {
      return member([memberSchema, 0], isMap ? "value" : "member");
    }
    throw new Error(`@smithy/core/schema - ${this.getName(true)} has no value member.`);
  }
  getMemberSchema(memberName) {
    const struct = this.getSchema();
    if (this.isStructSchema() && struct[4].includes(memberName)) {
      const i2 = struct[4].indexOf(memberName);
      const memberSchema = struct[5][i2];
      return member(isMemberSchema(memberSchema) ? memberSchema : [memberSchema, 0], memberName);
    }
    if (this.isDocumentSchema()) {
      return member([15, 0], memberName);
    }
    throw new Error(`@smithy/core/schema - ${this.getName(true)} has no no member=${memberName}.`);
  }
  getMemberSchemas() {
    const buffer = {};
    try {
      for (const [k2, v2] of this.structIterator()) {
        buffer[k2] = v2;
      }
    } catch (ignored) {
    }
    return buffer;
  }
  getEventStreamMember() {
    if (this.isStructSchema()) {
      for (const [memberName, memberSchema] of this.structIterator()) {
        if (memberSchema.isStreaming() && memberSchema.isStructSchema()) {
          return memberName;
        }
      }
    }
    return "";
  }
  *structIterator() {
    if (this.isUnitSchema()) {
      return;
    }
    if (!this.isStructSchema()) {
      throw new Error("@smithy/core/schema - cannot iterate non-struct schema.");
    }
    const struct = this.getSchema();
    for (let i2 = 0; i2 < struct[4].length; ++i2) {
      yield [struct[4][i2], member([struct[5][i2], 0], struct[4][i2])];
    }
  }
};
function member(memberSchema, memberName) {
  if (memberSchema instanceof NormalizedSchema) {
    return Object.assign(memberSchema, {
      memberName,
      _isMemberSchema: true
    });
  }
  const internalCtorAccess = NormalizedSchema;
  return new internalCtorAccess(memberSchema, memberName);
}
var isMemberSchema = (sc) => Array.isArray(sc) && sc.length === 2;
var isStaticSchema = (sc) => Array.isArray(sc) && sc.length >= 5;

// node_modules/@smithy/core/dist-es/submodules/serde/parse-utils.js
var parseBoolean = (value) => {
  switch (value) {
    case "true":
      return true;
    case "false":
      return false;
    default:
      throw new Error(`Unable to parse boolean value "${value}"`);
  }
};
var expectNumber = (value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "string") {
    const parsed = parseFloat(value);
    if (!Number.isNaN(parsed)) {
      if (String(parsed) !== String(value)) {
        logger.warn(stackTraceWarning(`Expected number but observed string: ${value}`));
      }
      return parsed;
    }
  }
  if (typeof value === "number") {
    return value;
  }
  throw new TypeError(`Expected number, got ${typeof value}: ${value}`);
};
var MAX_FLOAT = Math.ceil(2 ** 127 * (2 - 2 ** -23));
var expectFloat32 = (value) => {
  const expected = expectNumber(value);
  if (expected !== void 0 && !Number.isNaN(expected) && expected !== Infinity && expected !== -Infinity) {
    if (Math.abs(expected) > MAX_FLOAT) {
      throw new TypeError(`Expected 32-bit float, got ${value}`);
    }
  }
  return expected;
};
var expectLong = (value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (Number.isInteger(value) && !Number.isNaN(value)) {
    return value;
  }
  throw new TypeError(`Expected integer, got ${typeof value}: ${value}`);
};
var expectShort = (value) => expectSizedInt(value, 16);
var expectByte = (value) => expectSizedInt(value, 8);
var expectSizedInt = (value, size) => {
  const expected = expectLong(value);
  if (expected !== void 0 && castInt(expected, size) !== expected) {
    throw new TypeError(`Expected ${size}-bit integer, got ${value}`);
  }
  return expected;
};
var castInt = (value, size) => {
  switch (size) {
    case 32:
      return Int32Array.of(value)[0];
    case 16:
      return Int16Array.of(value)[0];
    case 8:
      return Int8Array.of(value)[0];
  }
};
var expectNonNull = (value, location) => {
  if (value === null || value === void 0) {
    if (location) {
      throw new TypeError(`Expected a non-null value for ${location}`);
    }
    throw new TypeError("Expected a non-null value");
  }
  return value;
};
var expectObject = (value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  const receivedType = Array.isArray(value) ? "array" : typeof value;
  throw new TypeError(`Expected object, got ${receivedType}: ${value}`);
};
var expectString = (value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value === "string") {
    return value;
  }
  if (["boolean", "number", "bigint"].includes(typeof value)) {
    logger.warn(stackTraceWarning(`Expected string, got ${typeof value}: ${value}`));
    return String(value);
  }
  throw new TypeError(`Expected string, got ${typeof value}: ${value}`);
};
var strictParseFloat32 = (value) => {
  if (typeof value == "string") {
    return expectFloat32(parseNumber(value));
  }
  return expectFloat32(value);
};
var NUMBER_REGEX = /(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|(-?Infinity)|(NaN)/g;
var parseNumber = (value) => {
  const matches = value.match(NUMBER_REGEX);
  if (matches === null || matches[0].length !== value.length) {
    throw new TypeError(`Expected real number, got implicit NaN`);
  }
  return parseFloat(value);
};
var strictParseLong = (value) => {
  if (typeof value === "string") {
    return expectLong(parseNumber(value));
  }
  return expectLong(value);
};
var strictParseShort = (value) => {
  if (typeof value === "string") {
    return expectShort(parseNumber(value));
  }
  return expectShort(value);
};
var strictParseByte = (value) => {
  if (typeof value === "string") {
    return expectByte(parseNumber(value));
  }
  return expectByte(value);
};
var stackTraceWarning = (message) => {
  return String(new TypeError(message).stack || message).split("\n").slice(0, 5).filter((s2) => !s2.includes("stackTraceWarning")).join("\n");
};
var logger = {
  warn: console.warn
};

// node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js
var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function dateToUtcString(date) {
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth();
  const dayOfWeek = date.getUTCDay();
  const dayOfMonthInt = date.getUTCDate();
  const hoursInt = date.getUTCHours();
  const minutesInt = date.getUTCMinutes();
  const secondsInt = date.getUTCSeconds();
  const dayOfMonthString = dayOfMonthInt < 10 ? `0${dayOfMonthInt}` : `${dayOfMonthInt}`;
  const hoursString = hoursInt < 10 ? `0${hoursInt}` : `${hoursInt}`;
  const minutesString = minutesInt < 10 ? `0${minutesInt}` : `${minutesInt}`;
  const secondsString = secondsInt < 10 ? `0${secondsInt}` : `${secondsInt}`;
  return `${DAYS[dayOfWeek]}, ${dayOfMonthString} ${MONTHS[month]} ${year} ${hoursString}:${minutesString}:${secondsString} GMT`;
}
var RFC3339 = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[zZ]$/);
var RFC3339_WITH_OFFSET = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(([-+]\d{2}\:\d{2})|[zZ])$/);
var parseRfc3339DateTimeWithOffset = (value) => {
  if (value === null || value === void 0) {
    return void 0;
  }
  if (typeof value !== "string") {
    throw new TypeError("RFC-3339 date-times must be expressed as strings");
  }
  const match = RFC3339_WITH_OFFSET.exec(value);
  if (!match) {
    throw new TypeError("Invalid RFC-3339 date-time value");
  }
  const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, offsetStr] = match;
  const year = strictParseShort(stripLeadingZeroes(yearStr));
  const month = parseDateValue(monthStr, "month", 1, 12);
  const day = parseDateValue(dayStr, "day", 1, 31);
  const date = buildDate(year, month, day, { hours, minutes, seconds, fractionalMilliseconds });
  if (offsetStr.toUpperCase() != "Z") {
    date.setTime(date.getTime() - parseOffsetToMilliseconds(offsetStr));
  }
  return date;
};
var IMF_FIXDATE = new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
var RFC_850_DATE = new RegExp(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
var ASC_TIME = new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})$/);
var buildDate = (year, month, day, time) => {
  const adjustedMonth = month - 1;
  validateDayOfMonth(year, adjustedMonth, day);
  return new Date(Date.UTC(year, adjustedMonth, day, parseDateValue(time.hours, "hour", 0, 23), parseDateValue(time.minutes, "minute", 0, 59), parseDateValue(time.seconds, "seconds", 0, 60), parseMilliseconds(time.fractionalMilliseconds)));
};
var FIFTY_YEARS_IN_MILLIS = 50 * 365 * 24 * 60 * 60 * 1e3;
var DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
var validateDayOfMonth = (year, month, day) => {
  let maxDays = DAYS_IN_MONTH[month];
  if (month === 1 && isLeapYear(year)) {
    maxDays = 29;
  }
  if (day > maxDays) {
    throw new TypeError(`Invalid day for ${MONTHS[month]} in ${year}: ${day}`);
  }
};
var isLeapYear = (year) => {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
};
var parseDateValue = (value, type, lower, upper) => {
  const dateVal = strictParseByte(stripLeadingZeroes(value));
  if (dateVal < lower || dateVal > upper) {
    throw new TypeError(`${type} must be between ${lower} and ${upper}, inclusive`);
  }
  return dateVal;
};
var parseMilliseconds = (value) => {
  if (value === null || value === void 0) {
    return 0;
  }
  return strictParseFloat32("0." + value) * 1e3;
};
var parseOffsetToMilliseconds = (value) => {
  const directionStr = value[0];
  let direction = 1;
  if (directionStr == "+") {
    direction = 1;
  } else if (directionStr == "-") {
    direction = -1;
  } else {
    throw new TypeError(`Offset direction, ${directionStr}, must be "+" or "-"`);
  }
  const hour = Number(value.substring(1, 3));
  const minute = Number(value.substring(4, 6));
  return direction * (hour * 60 + minute) * 60 * 1e3;
};
var stripLeadingZeroes = (value) => {
  let idx = 0;
  while (idx < value.length - 1 && value.charAt(idx) === "0") {
    idx++;
  }
  if (idx === 0) {
    return value;
  }
  return value.slice(idx);
};

// node_modules/@smithy/uuid/dist-es/randomUUID.browser.js
var randomUUID = typeof crypto !== "undefined" && crypto.randomUUID && crypto.randomUUID.bind(crypto);

// node_modules/@smithy/uuid/dist-es/v4.js
var decimalToHex = Array.from({ length: 256 }, (_, i2) => i2.toString(16).padStart(2, "0"));
var v4 = () => {
  if (randomUUID) {
    return randomUUID();
  }
  const rnds = new Uint8Array(16);
  crypto.getRandomValues(rnds);
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  return decimalToHex[rnds[0]] + decimalToHex[rnds[1]] + decimalToHex[rnds[2]] + decimalToHex[rnds[3]] + "-" + decimalToHex[rnds[4]] + decimalToHex[rnds[5]] + "-" + decimalToHex[rnds[6]] + decimalToHex[rnds[7]] + "-" + decimalToHex[rnds[8]] + decimalToHex[rnds[9]] + "-" + decimalToHex[rnds[10]] + decimalToHex[rnds[11]] + decimalToHex[rnds[12]] + decimalToHex[rnds[13]] + decimalToHex[rnds[14]] + decimalToHex[rnds[15]];
};

// node_modules/@smithy/core/dist-es/submodules/protocols/resolve-path.js
var resolvedPath = (resolvedPath2, input, memberName, labelValueProvider, uriLabel, isGreedyLabel) => {
  if (input != null && input[memberName] !== void 0) {
    const labelValue = labelValueProvider();
    if (labelValue.length <= 0) {
      throw new Error("Empty value provided for input HTTP label: " + memberName + ".");
    }
    resolvedPath2 = resolvedPath2.replace(uriLabel, isGreedyLabel ? labelValue.split("/").map((segment) => extendedEncodeURIComponent(segment)).join("/") : extendedEncodeURIComponent(labelValue));
  } else {
    throw new Error("No value provided for input HTTP label: " + memberName + ".");
  }
  return resolvedPath2;
};

// node_modules/@smithy/core/dist-es/submodules/protocols/requestBuilder.js
function requestBuilder(input, context) {
  return new RequestBuilder(input, context);
}
var RequestBuilder = class {
  input;
  context;
  query = {};
  method = "";
  headers = {};
  path = "";
  body = null;
  hostname = "";
  resolvePathStack = [];
  constructor(input, context) {
    this.input = input;
    this.context = context;
  }
  async build() {
    const { hostname, protocol = "https", port, path: basePath } = await this.context.endpoint();
    this.path = basePath;
    for (const resolvePath of this.resolvePathStack) {
      resolvePath(this.path);
    }
    return new HttpRequest({
      protocol,
      hostname: this.hostname || hostname,
      port,
      method: this.method,
      path: this.path,
      query: this.query,
      body: this.body,
      headers: this.headers
    });
  }
  hn(hostname) {
    this.hostname = hostname;
    return this;
  }
  bp(uriLabel) {
    this.resolvePathStack.push((basePath) => {
      this.path = `${basePath?.endsWith("/") ? basePath.slice(0, -1) : basePath || ""}` + uriLabel;
    });
    return this;
  }
  p(memberName, labelValueProvider, uriLabel, isGreedyLabel) {
    this.resolvePathStack.push((path) => {
      this.path = resolvedPath(path, this.input, memberName, labelValueProvider, uriLabel, isGreedyLabel);
    });
    return this;
  }
  h(headers) {
    this.headers = headers;
    return this;
  }
  q(query) {
    this.query = query;
    return this;
  }
  b(body) {
    this.body = body;
    return this;
  }
  m(method) {
    this.method = method;
    return this;
  }
};

// node_modules/@smithy/core/dist-es/setFeature.js
function setFeature2(context, feature, value) {
  if (!context.__smithy_context) {
    context.__smithy_context = {
      features: {}
    };
  } else if (!context.__smithy_context.features) {
    context.__smithy_context.features = {};
  }
  context.__smithy_context.features[feature] = value;
}

// node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js
var DefaultIdentityProviderConfig = class {
  authSchemes = /* @__PURE__ */ new Map();
  constructor(config) {
    for (const [key, value] of Object.entries(config)) {
      if (value !== void 0) {
        this.authSchemes.set(key, value);
      }
    }
  }
  getIdentityProvider(schemeId) {
    return this.authSchemes.get(schemeId);
  }
};

// node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js
var createIsIdentityExpiredFunction = (expirationMs) => function isIdentityExpired2(identity) {
  return doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs;
};
var EXPIRATION_MS = 3e5;
var isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
var doesIdentityRequireRefresh = (identity) => identity.expiration !== void 0;
var memoizeIdentityProvider = (provider, isExpired, requiresRefresh) => {
  if (provider === void 0) {
    return void 0;
  }
  const normalizedProvider = typeof provider !== "function" ? async () => Promise.resolve(provider) : provider;
  let resolved;
  let pending;
  let hasResult;
  let isConstant = false;
  const coalesceProvider = async (options) => {
    if (!pending) {
      pending = normalizedProvider(options);
    }
    try {
      resolved = await pending;
      hasResult = true;
      isConstant = false;
    } finally {
      pending = void 0;
    }
    return resolved;
  };
  if (isExpired === void 0) {
    return async (options) => {
      if (!hasResult || options?.forceRefresh) {
        resolved = await coalesceProvider(options);
      }
      return resolved;
    };
  }
  return async (options) => {
    if (!hasResult || options?.forceRefresh) {
      resolved = await coalesceProvider(options);
    }
    if (isConstant) {
      return resolved;
    }
    if (!requiresRefresh(resolved)) {
      isConstant = true;
      return resolved;
    }
    if (isExpired(resolved)) {
      await coalesceProvider(options);
      return resolved;
    }
    return resolved;
  };
};

// node_modules/@smithy/property-provider/dist-es/memoize.js
var memoize = (provider, isExpired, requiresRefresh) => {
  let resolved;
  let pending;
  let hasResult;
  let isConstant = false;
  const coalesceProvider = async () => {
    if (!pending) {
      pending = provider();
    }
    try {
      resolved = await pending;
      hasResult = true;
      isConstant = false;
    } finally {
      pending = void 0;
    }
    return resolved;
  };
  if (isExpired === void 0) {
    return async (options) => {
      if (!hasResult || options?.forceRefresh) {
        resolved = await coalesceProvider();
      }
      return resolved;
    };
  }
  return async (options) => {
    if (!hasResult || options?.forceRefresh) {
      resolved = await coalesceProvider();
    }
    if (isConstant) {
      return resolved;
    }
    if (requiresRefresh && !requiresRefresh(resolved)) {
      isConstant = true;
      return resolved;
    }
    if (isExpired(resolved)) {
      await coalesceProvider();
      return resolved;
    }
    return resolved;
  };
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js
var resolveAwsSdkSigV4AConfig = (config) => {
  config.sigv4aSigningRegionSet = normalizeProvider2(config.sigv4aSigningRegionSet);
  return config;
};

// node_modules/@smithy/signature-v4/dist-es/SignatureV4.js
init_dist_es();

// node_modules/@smithy/signature-v4/dist-es/constants.js
var ALGORITHM_QUERY_PARAM = "X-Amz-Algorithm";
var CREDENTIAL_QUERY_PARAM = "X-Amz-Credential";
var AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
var SIGNED_HEADERS_QUERY_PARAM = "X-Amz-SignedHeaders";
var EXPIRES_QUERY_PARAM = "X-Amz-Expires";
var SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
var TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
var AUTH_HEADER = "authorization";
var AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
var DATE_HEADER = "date";
var GENERATED_HEADERS = [AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER];
var SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
var SHA256_HEADER = "x-amz-content-sha256";
var TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();
var ALWAYS_UNSIGNABLE_HEADERS = {
  authorization: true,
  "cache-control": true,
  connection: true,
  expect: true,
  from: true,
  "keep-alive": true,
  "max-forwards": true,
  pragma: true,
  referer: true,
  te: true,
  trailer: true,
  "transfer-encoding": true,
  upgrade: true,
  "user-agent": true,
  "x-amzn-trace-id": true
};
var PROXY_HEADER_PATTERN = /^proxy-/;
var SEC_HEADER_PATTERN = /^sec-/;
var ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";
var EVENT_ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256-PAYLOAD";
var UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
var MAX_CACHE_SIZE = 50;
var KEY_TYPE_IDENTIFIER = "aws4_request";
var MAX_PRESIGNED_TTL = 60 * 60 * 24 * 7;

// node_modules/@smithy/signature-v4/dist-es/credentialDerivation.js
init_dist_es();
var signingKeyCache = {};
var cacheQueue = [];
var createScope = (shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;
var getSigningKey = async (sha256Constructor, credentials, shortDate, region, service) => {
  const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
  const cacheKey = `${shortDate}:${region}:${service}:${toHex(credsHash)}:${credentials.sessionToken}`;
  if (cacheKey in signingKeyCache) {
    return signingKeyCache[cacheKey];
  }
  cacheQueue.push(cacheKey);
  while (cacheQueue.length > MAX_CACHE_SIZE) {
    delete signingKeyCache[cacheQueue.shift()];
  }
  let key = `AWS4${credentials.secretAccessKey}`;
  for (const signable of [shortDate, region, service, KEY_TYPE_IDENTIFIER]) {
    key = await hmac(sha256Constructor, key, signable);
  }
  return signingKeyCache[cacheKey] = key;
};
var hmac = (ctor, secret, data) => {
  const hash = new ctor(secret);
  hash.update(toUint8Array(data));
  return hash.digest();
};

// node_modules/@smithy/signature-v4/dist-es/getCanonicalHeaders.js
var getCanonicalHeaders = ({ headers }, unsignableHeaders, signableHeaders) => {
  const canonical = {};
  for (const headerName of Object.keys(headers).sort()) {
    if (headers[headerName] == void 0) {
      continue;
    }
    const canonicalHeaderName = headerName.toLowerCase();
    if (canonicalHeaderName in ALWAYS_UNSIGNABLE_HEADERS || unsignableHeaders?.has(canonicalHeaderName) || PROXY_HEADER_PATTERN.test(canonicalHeaderName) || SEC_HEADER_PATTERN.test(canonicalHeaderName)) {
      if (!signableHeaders || signableHeaders && !signableHeaders.has(canonicalHeaderName)) {
        continue;
      }
    }
    canonical[canonicalHeaderName] = headers[headerName].trim().replace(/\s+/g, " ");
  }
  return canonical;
};

// node_modules/@smithy/is-array-buffer/dist-es/index.js
var isArrayBuffer = (arg) => typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer || Object.prototype.toString.call(arg) === "[object ArrayBuffer]";

// node_modules/@smithy/signature-v4/dist-es/getPayloadHash.js
init_dist_es();
var getPayloadHash = async ({ headers, body }, hashConstructor) => {
  for (const headerName of Object.keys(headers)) {
    if (headerName.toLowerCase() === SHA256_HEADER) {
      return headers[headerName];
    }
  }
  if (body == void 0) {
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  } else if (typeof body === "string" || ArrayBuffer.isView(body) || isArrayBuffer(body)) {
    const hashCtor = new hashConstructor();
    hashCtor.update(toUint8Array(body));
    return toHex(await hashCtor.digest());
  }
  return UNSIGNED_PAYLOAD;
};

// node_modules/@smithy/signature-v4/dist-es/HeaderFormatter.js
init_dist_es();
var HeaderFormatter = class {
  format(headers) {
    const chunks = [];
    for (const headerName of Object.keys(headers)) {
      const bytes = fromUtf8(headerName);
      chunks.push(Uint8Array.from([bytes.byteLength]), bytes, this.formatHeaderValue(headers[headerName]));
    }
    const out = new Uint8Array(chunks.reduce((carry, bytes) => carry + bytes.byteLength, 0));
    let position = 0;
    for (const chunk of chunks) {
      out.set(chunk, position);
      position += chunk.byteLength;
    }
    return out;
  }
  formatHeaderValue(header) {
    switch (header.type) {
      case "boolean":
        return Uint8Array.from([header.value ? 0 : 1]);
      case "byte":
        return Uint8Array.from([2, header.value]);
      case "short":
        const shortView = new DataView(new ArrayBuffer(3));
        shortView.setUint8(0, 3);
        shortView.setInt16(1, header.value, false);
        return new Uint8Array(shortView.buffer);
      case "integer":
        const intView = new DataView(new ArrayBuffer(5));
        intView.setUint8(0, 4);
        intView.setInt32(1, header.value, false);
        return new Uint8Array(intView.buffer);
      case "long":
        const longBytes = new Uint8Array(9);
        longBytes[0] = 5;
        longBytes.set(header.value.bytes, 1);
        return longBytes;
      case "binary":
        const binView = new DataView(new ArrayBuffer(3 + header.value.byteLength));
        binView.setUint8(0, 6);
        binView.setUint16(1, header.value.byteLength, false);
        const binBytes = new Uint8Array(binView.buffer);
        binBytes.set(header.value, 3);
        return binBytes;
      case "string":
        const utf8Bytes = fromUtf8(header.value);
        const strView = new DataView(new ArrayBuffer(3 + utf8Bytes.byteLength));
        strView.setUint8(0, 7);
        strView.setUint16(1, utf8Bytes.byteLength, false);
        const strBytes = new Uint8Array(strView.buffer);
        strBytes.set(utf8Bytes, 3);
        return strBytes;
      case "timestamp":
        const tsBytes = new Uint8Array(9);
        tsBytes[0] = 8;
        tsBytes.set(Int64.fromNumber(header.value.valueOf()).bytes, 1);
        return tsBytes;
      case "uuid":
        if (!UUID_PATTERN.test(header.value)) {
          throw new Error(`Invalid UUID received: ${header.value}`);
        }
        const uuidBytes = new Uint8Array(17);
        uuidBytes[0] = 9;
        uuidBytes.set(fromHex(header.value.replace(/\-/g, "")), 1);
        return uuidBytes;
    }
  }
};
var HEADER_VALUE_TYPE;
(function(HEADER_VALUE_TYPE3) {
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["boolTrue"] = 0] = "boolTrue";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["boolFalse"] = 1] = "boolFalse";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["byte"] = 2] = "byte";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["short"] = 3] = "short";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["integer"] = 4] = "integer";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["long"] = 5] = "long";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["byteArray"] = 6] = "byteArray";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["string"] = 7] = "string";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["timestamp"] = 8] = "timestamp";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["uuid"] = 9] = "uuid";
})(HEADER_VALUE_TYPE || (HEADER_VALUE_TYPE = {}));
var UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
var Int64 = class _Int64 {
  bytes;
  constructor(bytes) {
    this.bytes = bytes;
    if (bytes.byteLength !== 8) {
      throw new Error("Int64 buffers must be exactly 8 bytes");
    }
  }
  static fromNumber(number) {
    if (number > 9223372036854776e3 || number < -9223372036854776e3) {
      throw new Error(`${number} is too large (or, if negative, too small) to represent as an Int64`);
    }
    const bytes = new Uint8Array(8);
    for (let i2 = 7, remaining = Math.abs(Math.round(number)); i2 > -1 && remaining > 0; i2--, remaining /= 256) {
      bytes[i2] = remaining;
    }
    if (number < 0) {
      negate(bytes);
    }
    return new _Int64(bytes);
  }
  valueOf() {
    const bytes = this.bytes.slice(0);
    const negative = bytes[0] & 128;
    if (negative) {
      negate(bytes);
    }
    return parseInt(toHex(bytes), 16) * (negative ? -1 : 1);
  }
  toString() {
    return String(this.valueOf());
  }
};
function negate(bytes) {
  for (let i2 = 0; i2 < 8; i2++) {
    bytes[i2] ^= 255;
  }
  for (let i2 = 7; i2 > -1; i2--) {
    bytes[i2]++;
    if (bytes[i2] !== 0)
      break;
  }
}

// node_modules/@smithy/signature-v4/dist-es/headerUtil.js
var hasHeader = (soughtHeader, headers) => {
  soughtHeader = soughtHeader.toLowerCase();
  for (const headerName of Object.keys(headers)) {
    if (soughtHeader === headerName.toLowerCase()) {
      return true;
    }
  }
  return false;
};

// node_modules/@smithy/signature-v4/dist-es/moveHeadersToQuery.js
var moveHeadersToQuery = (request, options = {}) => {
  const { headers, query = {} } = HttpRequest.clone(request);
  for (const name of Object.keys(headers)) {
    const lname = name.toLowerCase();
    if (lname.slice(0, 6) === "x-amz-" && !options.unhoistableHeaders?.has(lname) || options.hoistableHeaders?.has(lname)) {
      query[name] = headers[name];
      delete headers[name];
    }
  }
  return {
    ...request,
    headers,
    query
  };
};

// node_modules/@smithy/signature-v4/dist-es/prepareRequest.js
var prepareRequest = (request) => {
  request = HttpRequest.clone(request);
  for (const headerName of Object.keys(request.headers)) {
    if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) {
      delete request.headers[headerName];
    }
  }
  return request;
};

// node_modules/@smithy/signature-v4/dist-es/SignatureV4Base.js
init_dist_es();

// node_modules/@smithy/signature-v4/dist-es/getCanonicalQuery.js
var getCanonicalQuery = ({ query = {} }) => {
  const keys = [];
  const serialized = {};
  for (const key of Object.keys(query)) {
    if (key.toLowerCase() === SIGNATURE_HEADER) {
      continue;
    }
    const encodedKey = escapeUri(key);
    keys.push(encodedKey);
    const value = query[key];
    if (typeof value === "string") {
      serialized[encodedKey] = `${encodedKey}=${escapeUri(value)}`;
    } else if (Array.isArray(value)) {
      serialized[encodedKey] = value.slice(0).reduce((encoded, value2) => encoded.concat([`${encodedKey}=${escapeUri(value2)}`]), []).sort().join("&");
    }
  }
  return keys.sort().map((key) => serialized[key]).filter((serialized2) => serialized2).join("&");
};

// node_modules/@smithy/signature-v4/dist-es/utilDate.js
var iso8601 = (time) => toDate(time).toISOString().replace(/\.\d{3}Z$/, "Z");
var toDate = (time) => {
  if (typeof time === "number") {
    return new Date(time * 1e3);
  }
  if (typeof time === "string") {
    if (Number(time)) {
      return new Date(Number(time) * 1e3);
    }
    return new Date(time);
  }
  return time;
};

// node_modules/@smithy/signature-v4/dist-es/SignatureV4Base.js
var SignatureV4Base = class {
  service;
  regionProvider;
  credentialProvider;
  sha256;
  uriEscapePath;
  applyChecksum;
  constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true }) {
    this.service = service;
    this.sha256 = sha256;
    this.uriEscapePath = uriEscapePath;
    this.applyChecksum = typeof applyChecksum === "boolean" ? applyChecksum : true;
    this.regionProvider = normalizeProvider(region);
    this.credentialProvider = normalizeProvider(credentials);
  }
  createCanonicalRequest(request, canonicalHeaders, payloadHash) {
    const sortedHeaders = Object.keys(canonicalHeaders).sort();
    return `${request.method}
${this.getCanonicalPath(request)}
${getCanonicalQuery(request)}
${sortedHeaders.map((name) => `${name}:${canonicalHeaders[name]}`).join("\n")}

${sortedHeaders.join(";")}
${payloadHash}`;
  }
  async createStringToSign(longDate, credentialScope, canonicalRequest, algorithmIdentifier) {
    const hash = new this.sha256();
    hash.update(toUint8Array(canonicalRequest));
    const hashedRequest = await hash.digest();
    return `${algorithmIdentifier}
${longDate}
${credentialScope}
${toHex(hashedRequest)}`;
  }
  getCanonicalPath({ path }) {
    if (this.uriEscapePath) {
      const normalizedPathSegments = [];
      for (const pathSegment of path.split("/")) {
        if (pathSegment?.length === 0)
          continue;
        if (pathSegment === ".")
          continue;
        if (pathSegment === "..") {
          normalizedPathSegments.pop();
        } else {
          normalizedPathSegments.push(pathSegment);
        }
      }
      const normalizedPath = `${path?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && path?.endsWith("/") ? "/" : ""}`;
      const doubleEncoded = escapeUri(normalizedPath);
      return doubleEncoded.replace(/%2F/g, "/");
    }
    return path;
  }
  validateResolvedCredentials(credentials) {
    if (typeof credentials !== "object" || typeof credentials.accessKeyId !== "string" || typeof credentials.secretAccessKey !== "string") {
      throw new Error("Resolved credential object is not valid");
    }
  }
  formatDate(now) {
    const longDate = iso8601(now).replace(/[\-:]/g, "");
    return {
      longDate,
      shortDate: longDate.slice(0, 8)
    };
  }
  getCanonicalHeaderList(headers) {
    return Object.keys(headers).sort().join(";");
  }
};

// node_modules/@smithy/signature-v4/dist-es/SignatureV4.js
var SignatureV4 = class extends SignatureV4Base {
  headerFormatter = new HeaderFormatter();
  constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true }) {
    super({
      applyChecksum,
      credentials,
      region,
      service,
      sha256,
      uriEscapePath
    });
  }
  async presign(originalRequest, options = {}) {
    const { signingDate = /* @__PURE__ */ new Date(), expiresIn = 3600, unsignableHeaders, unhoistableHeaders, signableHeaders, hoistableHeaders, signingRegion, signingService } = options;
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? await this.regionProvider();
    const { longDate, shortDate } = this.formatDate(signingDate);
    if (expiresIn > MAX_PRESIGNED_TTL) {
      return Promise.reject("Signature version 4 presigned URLs must have an expiration date less than one week in the future");
    }
    const scope = createScope(shortDate, region, signingService ?? this.service);
    const request = moveHeadersToQuery(prepareRequest(originalRequest), { unhoistableHeaders, hoistableHeaders });
    if (credentials.sessionToken) {
      request.query[TOKEN_QUERY_PARAM] = credentials.sessionToken;
    }
    request.query[ALGORITHM_QUERY_PARAM] = ALGORITHM_IDENTIFIER;
    request.query[CREDENTIAL_QUERY_PARAM] = `${credentials.accessKeyId}/${scope}`;
    request.query[AMZ_DATE_QUERY_PARAM] = longDate;
    request.query[EXPIRES_QUERY_PARAM] = expiresIn.toString(10);
    const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
    request.query[SIGNED_HEADERS_QUERY_PARAM] = this.getCanonicalHeaderList(canonicalHeaders);
    request.query[SIGNATURE_QUERY_PARAM] = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request, canonicalHeaders, await getPayloadHash(originalRequest, this.sha256)));
    return request;
  }
  async sign(toSign, options) {
    if (typeof toSign === "string") {
      return this.signString(toSign, options);
    } else if (toSign.headers && toSign.payload) {
      return this.signEvent(toSign, options);
    } else if (toSign.message) {
      return this.signMessage(toSign, options);
    } else {
      return this.signRequest(toSign, options);
    }
  }
  async signEvent({ headers, payload }, { signingDate = /* @__PURE__ */ new Date(), priorSignature, signingRegion, signingService }) {
    const region = signingRegion ?? await this.regionProvider();
    const { shortDate, longDate } = this.formatDate(signingDate);
    const scope = createScope(shortDate, region, signingService ?? this.service);
    const hashedPayload = await getPayloadHash({ headers: {}, body: payload }, this.sha256);
    const hash = new this.sha256();
    hash.update(headers);
    const hashedHeaders = toHex(await hash.digest());
    const stringToSign = [
      EVENT_ALGORITHM_IDENTIFIER,
      longDate,
      scope,
      priorSignature,
      hashedHeaders,
      hashedPayload
    ].join("\n");
    return this.signString(stringToSign, { signingDate, signingRegion: region, signingService });
  }
  async signMessage(signableMessage, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService }) {
    const promise = this.signEvent({
      headers: this.headerFormatter.format(signableMessage.message.headers),
      payload: signableMessage.message.body
    }, {
      signingDate,
      signingRegion,
      signingService,
      priorSignature: signableMessage.priorSignature
    });
    return promise.then((signature) => {
      return { message: signableMessage.message, signature };
    });
  }
  async signString(stringToSign, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService } = {}) {
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? await this.regionProvider();
    const { shortDate } = this.formatDate(signingDate);
    const hash = new this.sha256(await this.getSigningKey(credentials, region, shortDate, signingService));
    hash.update(toUint8Array(stringToSign));
    return toHex(await hash.digest());
  }
  async signRequest(requestToSign, { signingDate = /* @__PURE__ */ new Date(), signableHeaders, unsignableHeaders, signingRegion, signingService } = {}) {
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? await this.regionProvider();
    const request = prepareRequest(requestToSign);
    const { longDate, shortDate } = this.formatDate(signingDate);
    const scope = createScope(shortDate, region, signingService ?? this.service);
    request.headers[AMZ_DATE_HEADER] = longDate;
    if (credentials.sessionToken) {
      request.headers[TOKEN_HEADER] = credentials.sessionToken;
    }
    const payloadHash = await getPayloadHash(request, this.sha256);
    if (!hasHeader(SHA256_HEADER, request.headers) && this.applyChecksum) {
      request.headers[SHA256_HEADER] = payloadHash;
    }
    const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
    const signature = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request, canonicalHeaders, payloadHash));
    request.headers[AUTH_HEADER] = `${ALGORITHM_IDENTIFIER} Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${this.getCanonicalHeaderList(canonicalHeaders)}, Signature=${signature}`;
    return request;
  }
  async getSignature(longDate, credentialScope, keyPromise, canonicalRequest) {
    const stringToSign = await this.createStringToSign(longDate, credentialScope, canonicalRequest, ALGORITHM_IDENTIFIER);
    const hash = new this.sha256(await keyPromise);
    hash.update(toUint8Array(stringToSign));
    return toHex(await hash.digest());
  }
  getSigningKey(credentials, region, shortDate, service) {
    return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
  }
};

// node_modules/@smithy/signature-v4/dist-es/signature-v4a-container.js
var signatureV4aContainer = {
  SignatureV4a: null
};

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js
var resolveAwsSdkSigV4Config = (config) => {
  let inputCredentials = config.credentials;
  let isUserSupplied = !!config.credentials;
  let resolvedCredentials = void 0;
  Object.defineProperty(config, "credentials", {
    set(credentials) {
      if (credentials && credentials !== inputCredentials && credentials !== resolvedCredentials) {
        isUserSupplied = true;
      }
      inputCredentials = credentials;
      const memoizedProvider = normalizeCredentialProvider(config, {
        credentials: inputCredentials,
        credentialDefaultProvider: config.credentialDefaultProvider
      });
      const boundProvider = bindCallerConfig(config, memoizedProvider);
      if (isUserSupplied && !boundProvider.attributed) {
        resolvedCredentials = async (options) => boundProvider(options).then((creds) => setCredentialFeature(creds, "CREDENTIALS_CODE", "e"));
        resolvedCredentials.memoized = boundProvider.memoized;
        resolvedCredentials.configBound = boundProvider.configBound;
        resolvedCredentials.attributed = true;
      } else {
        resolvedCredentials = boundProvider;
      }
    },
    get() {
      return resolvedCredentials;
    },
    enumerable: true,
    configurable: true
  });
  config.credentials = inputCredentials;
  const { signingEscapePath = true, systemClockOffset = config.systemClockOffset || 0, sha256 } = config;
  let signer;
  if (config.signer) {
    signer = normalizeProvider2(config.signer);
  } else if (config.regionInfoProvider) {
    signer = () => normalizeProvider2(config.region)().then(async (region) => [
      await config.regionInfoProvider(region, {
        useFipsEndpoint: await config.useFipsEndpoint(),
        useDualstackEndpoint: await config.useDualstackEndpoint()
      }) || {},
      region
    ]).then(([regionInfo, region]) => {
      const { signingRegion, signingService } = regionInfo;
      config.signingRegion = config.signingRegion || signingRegion || region;
      config.signingName = config.signingName || signingService || config.serviceId;
      const params = {
        ...config,
        credentials: config.credentials,
        region: config.signingRegion,
        service: config.signingName,
        sha256,
        uriEscapePath: signingEscapePath
      };
      const SignerCtor = config.signerConstructor || SignatureV4;
      return new SignerCtor(params);
    });
  } else {
    signer = async (authScheme) => {
      authScheme = Object.assign({}, {
        name: "sigv4",
        signingName: config.signingName || config.defaultSigningName,
        signingRegion: await normalizeProvider2(config.region)(),
        properties: {}
      }, authScheme);
      const signingRegion = authScheme.signingRegion;
      const signingService = authScheme.signingName;
      config.signingRegion = config.signingRegion || signingRegion;
      config.signingName = config.signingName || signingService || config.serviceId;
      const params = {
        ...config,
        credentials: config.credentials,
        region: config.signingRegion,
        service: config.signingName,
        sha256,
        uriEscapePath: signingEscapePath
      };
      const SignerCtor = config.signerConstructor || SignatureV4;
      return new SignerCtor(params);
    };
  }
  const resolvedConfig = Object.assign(config, {
    systemClockOffset,
    signingEscapePath,
    signer
  });
  return resolvedConfig;
};
function normalizeCredentialProvider(config, { credentials, credentialDefaultProvider }) {
  let credentialsProvider;
  if (credentials) {
    if (!credentials?.memoized) {
      credentialsProvider = memoizeIdentityProvider(credentials, isIdentityExpired, doesIdentityRequireRefresh);
    } else {
      credentialsProvider = credentials;
    }
  } else {
    if (credentialDefaultProvider) {
      credentialsProvider = normalizeProvider2(credentialDefaultProvider(Object.assign({}, config, {
        parentClientConfig: config
      })));
    } else {
      credentialsProvider = async () => {
        throw new Error("@aws-sdk/core::resolveAwsSdkSigV4Config - `credentials` not provided and no credentialDefaultProvider was configured.");
      };
    }
  }
  credentialsProvider.memoized = true;
  return credentialsProvider;
}
function bindCallerConfig(config, credentialsProvider) {
  if (credentialsProvider.configBound) {
    return credentialsProvider;
  }
  const fn = async (options) => credentialsProvider({ ...options, callerClientConfig: config });
  fn.memoized = credentialsProvider.memoized;
  fn.configBound = true;
  return fn;
}

// node_modules/@smithy/util-body-length-browser/dist-es/calculateBodyLength.js
var TEXT_ENCODER = typeof TextEncoder == "function" ? new TextEncoder() : null;
var calculateBodyLength = (body) => {
  if (typeof body === "string") {
    if (TEXT_ENCODER) {
      return TEXT_ENCODER.encode(body).byteLength;
    }
    let len = body.length;
    for (let i2 = len - 1; i2 >= 0; i2--) {
      const code = body.charCodeAt(i2);
      if (code > 127 && code <= 2047)
        len++;
      else if (code > 2047 && code <= 65535)
        len += 2;
      if (code >= 56320 && code <= 57343)
        i2--;
    }
    return len;
  } else if (typeof body.byteLength === "number") {
    return body.byteLength;
  } else if (typeof body.size === "number") {
    return body.size;
  }
  throw new Error(`Body Length computation failed for ${body}`);
};

// node_modules/@smithy/middleware-stack/dist-es/MiddlewareStack.js
var getAllAliases = (name, aliases) => {
  const _aliases = [];
  if (name) {
    _aliases.push(name);
  }
  if (aliases) {
    for (const alias of aliases) {
      _aliases.push(alias);
    }
  }
  return _aliases;
};
var getMiddlewareNameWithAliases = (name, aliases) => {
  return `${name || "anonymous"}${aliases && aliases.length > 0 ? ` (a.k.a. ${aliases.join(",")})` : ""}`;
};
var constructStack = () => {
  let absoluteEntries = [];
  let relativeEntries = [];
  let identifyOnResolve = false;
  const entriesNameSet = /* @__PURE__ */ new Set();
  const sort = (entries) => entries.sort((a2, b2) => stepWeights[b2.step] - stepWeights[a2.step] || priorityWeights[b2.priority || "normal"] - priorityWeights[a2.priority || "normal"]);
  const removeByName = (toRemove) => {
    let isRemoved = false;
    const filterCb = (entry) => {
      const aliases = getAllAliases(entry.name, entry.aliases);
      if (aliases.includes(toRemove)) {
        isRemoved = true;
        for (const alias of aliases) {
          entriesNameSet.delete(alias);
        }
        return false;
      }
      return true;
    };
    absoluteEntries = absoluteEntries.filter(filterCb);
    relativeEntries = relativeEntries.filter(filterCb);
    return isRemoved;
  };
  const removeByReference = (toRemove) => {
    let isRemoved = false;
    const filterCb = (entry) => {
      if (entry.middleware === toRemove) {
        isRemoved = true;
        for (const alias of getAllAliases(entry.name, entry.aliases)) {
          entriesNameSet.delete(alias);
        }
        return false;
      }
      return true;
    };
    absoluteEntries = absoluteEntries.filter(filterCb);
    relativeEntries = relativeEntries.filter(filterCb);
    return isRemoved;
  };
  const cloneTo = (toStack) => {
    absoluteEntries.forEach((entry) => {
      toStack.add(entry.middleware, { ...entry });
    });
    relativeEntries.forEach((entry) => {
      toStack.addRelativeTo(entry.middleware, { ...entry });
    });
    toStack.identifyOnResolve?.(stack.identifyOnResolve());
    return toStack;
  };
  const expandRelativeMiddlewareList = (from) => {
    const expandedMiddlewareList = [];
    from.before.forEach((entry) => {
      if (entry.before.length === 0 && entry.after.length === 0) {
        expandedMiddlewareList.push(entry);
      } else {
        expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
      }
    });
    expandedMiddlewareList.push(from);
    from.after.reverse().forEach((entry) => {
      if (entry.before.length === 0 && entry.after.length === 0) {
        expandedMiddlewareList.push(entry);
      } else {
        expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
      }
    });
    return expandedMiddlewareList;
  };
  const getMiddlewareList = (debug = false) => {
    const normalizedAbsoluteEntries = [];
    const normalizedRelativeEntries = [];
    const normalizedEntriesNameMap = {};
    absoluteEntries.forEach((entry) => {
      const normalizedEntry = {
        ...entry,
        before: [],
        after: []
      };
      for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
        normalizedEntriesNameMap[alias] = normalizedEntry;
      }
      normalizedAbsoluteEntries.push(normalizedEntry);
    });
    relativeEntries.forEach((entry) => {
      const normalizedEntry = {
        ...entry,
        before: [],
        after: []
      };
      for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
        normalizedEntriesNameMap[alias] = normalizedEntry;
      }
      normalizedRelativeEntries.push(normalizedEntry);
    });
    normalizedRelativeEntries.forEach((entry) => {
      if (entry.toMiddleware) {
        const toMiddleware = normalizedEntriesNameMap[entry.toMiddleware];
        if (toMiddleware === void 0) {
          if (debug) {
            return;
          }
          throw new Error(`${entry.toMiddleware} is not found when adding ${getMiddlewareNameWithAliases(entry.name, entry.aliases)} middleware ${entry.relation} ${entry.toMiddleware}`);
        }
        if (entry.relation === "after") {
          toMiddleware.after.push(entry);
        }
        if (entry.relation === "before") {
          toMiddleware.before.push(entry);
        }
      }
    });
    const mainChain = sort(normalizedAbsoluteEntries).map(expandRelativeMiddlewareList).reduce((wholeList, expandedMiddlewareList) => {
      wholeList.push(...expandedMiddlewareList);
      return wholeList;
    }, []);
    return mainChain;
  };
  const stack = {
    add: (middleware, options = {}) => {
      const { name, override, aliases: _aliases } = options;
      const entry = {
        step: "initialize",
        priority: "normal",
        middleware,
        ...options
      };
      const aliases = getAllAliases(name, _aliases);
      if (aliases.length > 0) {
        if (aliases.some((alias) => entriesNameSet.has(alias))) {
          if (!override)
            throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
          for (const alias of aliases) {
            const toOverrideIndex = absoluteEntries.findIndex((entry2) => entry2.name === alias || entry2.aliases?.some((a2) => a2 === alias));
            if (toOverrideIndex === -1) {
              continue;
            }
            const toOverride = absoluteEntries[toOverrideIndex];
            if (toOverride.step !== entry.step || entry.priority !== toOverride.priority) {
              throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware with ${toOverride.priority} priority in ${toOverride.step} step cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware with ${entry.priority} priority in ${entry.step} step.`);
            }
            absoluteEntries.splice(toOverrideIndex, 1);
          }
        }
        for (const alias of aliases) {
          entriesNameSet.add(alias);
        }
      }
      absoluteEntries.push(entry);
    },
    addRelativeTo: (middleware, options) => {
      const { name, override, aliases: _aliases } = options;
      const entry = {
        middleware,
        ...options
      };
      const aliases = getAllAliases(name, _aliases);
      if (aliases.length > 0) {
        if (aliases.some((alias) => entriesNameSet.has(alias))) {
          if (!override)
            throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
          for (const alias of aliases) {
            const toOverrideIndex = relativeEntries.findIndex((entry2) => entry2.name === alias || entry2.aliases?.some((a2) => a2 === alias));
            if (toOverrideIndex === -1) {
              continue;
            }
            const toOverride = relativeEntries[toOverrideIndex];
            if (toOverride.toMiddleware !== entry.toMiddleware || toOverride.relation !== entry.relation) {
              throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware ${toOverride.relation} "${toOverride.toMiddleware}" middleware cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware ${entry.relation} "${entry.toMiddleware}" middleware.`);
            }
            relativeEntries.splice(toOverrideIndex, 1);
          }
        }
        for (const alias of aliases) {
          entriesNameSet.add(alias);
        }
      }
      relativeEntries.push(entry);
    },
    clone: () => cloneTo(constructStack()),
    use: (plugin) => {
      plugin.applyToStack(stack);
    },
    remove: (toRemove) => {
      if (typeof toRemove === "string")
        return removeByName(toRemove);
      else
        return removeByReference(toRemove);
    },
    removeByTag: (toRemove) => {
      let isRemoved = false;
      const filterCb = (entry) => {
        const { tags, name, aliases: _aliases } = entry;
        if (tags && tags.includes(toRemove)) {
          const aliases = getAllAliases(name, _aliases);
          for (const alias of aliases) {
            entriesNameSet.delete(alias);
          }
          isRemoved = true;
          return false;
        }
        return true;
      };
      absoluteEntries = absoluteEntries.filter(filterCb);
      relativeEntries = relativeEntries.filter(filterCb);
      return isRemoved;
    },
    concat: (from) => {
      const cloned = cloneTo(constructStack());
      cloned.use(from);
      cloned.identifyOnResolve(identifyOnResolve || cloned.identifyOnResolve() || (from.identifyOnResolve?.() ?? false));
      return cloned;
    },
    applyToStack: cloneTo,
    identify: () => {
      return getMiddlewareList(true).map((mw) => {
        const step = mw.step ?? mw.relation + " " + mw.toMiddleware;
        return getMiddlewareNameWithAliases(mw.name, mw.aliases) + " - " + step;
      });
    },
    identifyOnResolve(toggle) {
      if (typeof toggle === "boolean")
        identifyOnResolve = toggle;
      return identifyOnResolve;
    },
    resolve: (handler2, context) => {
      for (const middleware of getMiddlewareList().map((entry) => entry.middleware).reverse()) {
        handler2 = middleware(handler2, context);
      }
      if (identifyOnResolve) {
        console.log(stack.identify());
      }
      return handler2;
    }
  };
  return stack;
};
var stepWeights = {
  initialize: 5,
  serialize: 4,
  build: 3,
  finalizeRequest: 2,
  deserialize: 1
};
var priorityWeights = {
  high: 3,
  normal: 2,
  low: 1
};

// node_modules/@smithy/smithy-client/dist-es/client.js
var Client = class {
  config;
  middlewareStack = constructStack();
  initConfig;
  handlers;
  constructor(config) {
    this.config = config;
  }
  send(command, optionsOrCb, cb2) {
    const options = typeof optionsOrCb !== "function" ? optionsOrCb : void 0;
    const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb2;
    const useHandlerCache = options === void 0 && this.config.cacheMiddleware === true;
    let handler2;
    if (useHandlerCache) {
      if (!this.handlers) {
        this.handlers = /* @__PURE__ */ new WeakMap();
      }
      const handlers = this.handlers;
      if (handlers.has(command.constructor)) {
        handler2 = handlers.get(command.constructor);
      } else {
        handler2 = command.resolveMiddleware(this.middlewareStack, this.config, options);
        handlers.set(command.constructor, handler2);
      }
    } else {
      delete this.handlers;
      handler2 = command.resolveMiddleware(this.middlewareStack, this.config, options);
    }
    if (callback) {
      handler2(command).then((result) => callback(null, result.output), (err) => callback(err)).catch(() => {
      });
    } else {
      return handler2(command).then((result) => result.output);
    }
  }
  destroy() {
    this.config?.requestHandler?.destroy?.();
    delete this.handlers;
  }
};

// node_modules/@smithy/smithy-client/dist-es/schemaLogFilter.js
var SENSITIVE_STRING = "***SensitiveInformation***";
function schemaLogFilter(schema, data) {
  if (data == null) {
    return data;
  }
  const ns = NormalizedSchema.of(schema);
  if (ns.getMergedTraits().sensitive) {
    return SENSITIVE_STRING;
  }
  if (ns.isListSchema()) {
    const isSensitive = !!ns.getValueSchema().getMergedTraits().sensitive;
    if (isSensitive) {
      return SENSITIVE_STRING;
    }
  } else if (ns.isMapSchema()) {
    const isSensitive = !!ns.getKeySchema().getMergedTraits().sensitive || !!ns.getValueSchema().getMergedTraits().sensitive;
    if (isSensitive) {
      return SENSITIVE_STRING;
    }
  } else if (ns.isStructSchema() && typeof data === "object") {
    const object = data;
    const newObject = {};
    for (const [member2, memberNs] of ns.structIterator()) {
      if (object[member2] != null) {
        newObject[member2] = schemaLogFilter(memberNs, object[member2]);
      }
    }
    return newObject;
  }
  return data;
}

// node_modules/@smithy/smithy-client/dist-es/command.js
var Command = class {
  middlewareStack = constructStack();
  schema;
  static classBuilder() {
    return new ClassBuilder();
  }
  resolveMiddlewareWithContext(clientStack, configuration, options, { middlewareFn, clientName, commandName, inputFilterSensitiveLog, outputFilterSensitiveLog, smithyContext, additionalContext, CommandCtor }) {
    for (const mw of middlewareFn.bind(this)(CommandCtor, clientStack, configuration, options)) {
      this.middlewareStack.use(mw);
    }
    const stack = clientStack.concat(this.middlewareStack);
    const { logger: logger2 } = configuration;
    const handlerExecutionContext = {
      logger: logger2,
      clientName,
      commandName,
      inputFilterSensitiveLog,
      outputFilterSensitiveLog,
      [SMITHY_CONTEXT_KEY]: {
        commandInstance: this,
        ...smithyContext
      },
      ...additionalContext
    };
    const { requestHandler } = configuration;
    return stack.resolve((request) => requestHandler.handle(request.request, options || {}), handlerExecutionContext);
  }
};
var ClassBuilder = class {
  _init = () => {
  };
  _ep = {};
  _middlewareFn = () => [];
  _commandName = "";
  _clientName = "";
  _additionalContext = {};
  _smithyContext = {};
  _inputFilterSensitiveLog = void 0;
  _outputFilterSensitiveLog = void 0;
  _serializer = null;
  _deserializer = null;
  _operationSchema;
  init(cb2) {
    this._init = cb2;
  }
  ep(endpointParameterInstructions) {
    this._ep = endpointParameterInstructions;
    return this;
  }
  m(middlewareSupplier) {
    this._middlewareFn = middlewareSupplier;
    return this;
  }
  s(service, operation, smithyContext = {}) {
    this._smithyContext = {
      service,
      operation,
      ...smithyContext
    };
    return this;
  }
  c(additionalContext = {}) {
    this._additionalContext = additionalContext;
    return this;
  }
  n(clientName, commandName) {
    this._clientName = clientName;
    this._commandName = commandName;
    return this;
  }
  f(inputFilter = (_) => _, outputFilter = (_) => _) {
    this._inputFilterSensitiveLog = inputFilter;
    this._outputFilterSensitiveLog = outputFilter;
    return this;
  }
  ser(serializer) {
    this._serializer = serializer;
    return this;
  }
  de(deserializer) {
    this._deserializer = deserializer;
    return this;
  }
  sc(operation) {
    this._operationSchema = operation;
    this._smithyContext.operationSchema = operation;
    return this;
  }
  build() {
    const closure = this;
    let CommandRef;
    return CommandRef = class extends Command {
      input;
      static getEndpointParameterInstructions() {
        return closure._ep;
      }
      constructor(...[input]) {
        super();
        this.input = input ?? {};
        closure._init(this);
        this.schema = closure._operationSchema;
      }
      resolveMiddleware(stack, configuration, options) {
        const op = closure._operationSchema;
        const input = op?.[4] ?? op?.input;
        const output = op?.[5] ?? op?.output;
        return this.resolveMiddlewareWithContext(stack, configuration, options, {
          CommandCtor: CommandRef,
          middlewareFn: closure._middlewareFn,
          clientName: closure._clientName,
          commandName: closure._commandName,
          inputFilterSensitiveLog: closure._inputFilterSensitiveLog ?? (op ? schemaLogFilter.bind(null, input) : (_) => _),
          outputFilterSensitiveLog: closure._outputFilterSensitiveLog ?? (op ? schemaLogFilter.bind(null, output) : (_) => _),
          smithyContext: closure._smithyContext,
          additionalContext: closure._additionalContext
        });
      }
      serialize = closure._serializer;
      deserialize = closure._deserializer;
    };
  }
};

// node_modules/@smithy/smithy-client/dist-es/constants.js
var SENSITIVE_STRING2 = "***SensitiveInformation***";

// node_modules/@smithy/smithy-client/dist-es/exceptions.js
var ServiceException = class _ServiceException extends Error {
  $fault;
  $response;
  $retryable;
  $metadata;
  constructor(options) {
    super(options.message);
    Object.setPrototypeOf(this, Object.getPrototypeOf(this).constructor.prototype);
    this.name = options.name;
    this.$fault = options.$fault;
    this.$metadata = options.$metadata;
  }
  static isInstance(value) {
    if (!value)
      return false;
    const candidate = value;
    return _ServiceException.prototype.isPrototypeOf(candidate) || Boolean(candidate.$fault) && Boolean(candidate.$metadata) && (candidate.$fault === "client" || candidate.$fault === "server");
  }
  static [Symbol.hasInstance](instance) {
    if (!instance)
      return false;
    const candidate = instance;
    if (this === _ServiceException) {
      return _ServiceException.isInstance(instance);
    }
    if (_ServiceException.isInstance(instance)) {
      if (candidate.name && this.name) {
        return this.prototype.isPrototypeOf(instance) || candidate.name === this.name;
      }
      return this.prototype.isPrototypeOf(instance);
    }
    return false;
  }
};
var decorateServiceException = (exception, additions = {}) => {
  Object.entries(additions).filter(([, v2]) => v2 !== void 0).forEach(([k2, v2]) => {
    if (exception[k2] == void 0 || exception[k2] === "") {
      exception[k2] = v2;
    }
  });
  const message = exception.message || exception.Message || "UnknownError";
  exception.message = message;
  delete exception.Message;
  return exception;
};

// node_modules/@smithy/smithy-client/dist-es/default-error-handler.js
var throwDefaultError = ({ output, parsedBody, exceptionCtor, errorCode }) => {
  const $metadata = deserializeMetadata(output);
  const statusCode = $metadata.httpStatusCode ? $metadata.httpStatusCode + "" : void 0;
  const response = new exceptionCtor({
    name: parsedBody?.code || parsedBody?.Code || errorCode || statusCode || "UnknownError",
    $fault: "client",
    $metadata
  });
  throw decorateServiceException(response, parsedBody);
};
var withBaseException = (ExceptionCtor) => {
  return ({ output, parsedBody, errorCode }) => {
    throwDefaultError({ output, parsedBody, exceptionCtor: ExceptionCtor, errorCode });
  };
};
var deserializeMetadata = (output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
});

// node_modules/@smithy/smithy-client/dist-es/defaults-mode.js
var loadConfigsForDefaultMode = (mode) => {
  switch (mode) {
    case "standard":
      return {
        retryMode: "standard",
        connectionTimeout: 3100
      };
    case "in-region":
      return {
        retryMode: "standard",
        connectionTimeout: 1100
      };
    case "cross-region":
      return {
        retryMode: "standard",
        connectionTimeout: 3100
      };
    case "mobile":
      return {
        retryMode: "standard",
        connectionTimeout: 3e4
      };
    default:
      return {};
  }
};

// node_modules/@smithy/smithy-client/dist-es/extensions/checksum.js
var getChecksumConfiguration = (runtimeConfig) => {
  const checksumAlgorithms = [];
  for (const id in AlgorithmId) {
    const algorithmId = AlgorithmId[id];
    if (runtimeConfig[algorithmId] === void 0) {
      continue;
    }
    checksumAlgorithms.push({
      algorithmId: () => algorithmId,
      checksumConstructor: () => runtimeConfig[algorithmId]
    });
  }
  return {
    addChecksumAlgorithm(algo) {
      checksumAlgorithms.push(algo);
    },
    checksumAlgorithms() {
      return checksumAlgorithms;
    }
  };
};
var resolveChecksumRuntimeConfig = (clientConfig) => {
  const runtimeConfig = {};
  clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
    runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
  });
  return runtimeConfig;
};

// node_modules/@smithy/smithy-client/dist-es/extensions/retry.js
var getRetryConfiguration = (runtimeConfig) => {
  return {
    setRetryStrategy(retryStrategy) {
      runtimeConfig.retryStrategy = retryStrategy;
    },
    retryStrategy() {
      return runtimeConfig.retryStrategy;
    }
  };
};
var resolveRetryRuntimeConfig = (retryStrategyConfiguration) => {
  const runtimeConfig = {};
  runtimeConfig.retryStrategy = retryStrategyConfiguration.retryStrategy();
  return runtimeConfig;
};

// node_modules/@smithy/smithy-client/dist-es/extensions/defaultExtensionConfiguration.js
var getDefaultExtensionConfiguration = (runtimeConfig) => {
  return Object.assign(getChecksumConfiguration(runtimeConfig), getRetryConfiguration(runtimeConfig));
};
var resolveDefaultRuntimeConfig = (config) => {
  return Object.assign(resolveChecksumRuntimeConfig(config), resolveRetryRuntimeConfig(config));
};

// node_modules/@smithy/smithy-client/dist-es/get-value-from-text-node.js
var getValueFromTextNode = (obj) => {
  const textNodeName = "#text";
  for (const key in obj) {
    if (obj.hasOwnProperty(key) && obj[key][textNodeName] !== void 0) {
      obj[key] = obj[key][textNodeName];
    } else if (typeof obj[key] === "object" && obj[key] !== null) {
      obj[key] = getValueFromTextNode(obj[key]);
    }
  }
  return obj;
};

// node_modules/@smithy/smithy-client/dist-es/is-serializable-header-value.js
var isSerializableHeaderValue = (value) => {
  return value != null;
};

// node_modules/@smithy/smithy-client/dist-es/NoOpLogger.js
var NoOpLogger = class {
  trace() {
  }
  debug() {
  }
  info() {
  }
  warn() {
  }
  error() {
  }
};

// node_modules/@smithy/smithy-client/dist-es/object-mapping.js
function map(arg0, arg1, arg2) {
  let target;
  let filter;
  let instructions;
  if (typeof arg1 === "undefined" && typeof arg2 === "undefined") {
    target = {};
    instructions = arg0;
  } else {
    target = arg0;
    if (typeof arg1 === "function") {
      filter = arg1;
      instructions = arg2;
      return mapWithFilter(target, filter, instructions);
    } else {
      instructions = arg1;
    }
  }
  for (const key of Object.keys(instructions)) {
    if (!Array.isArray(instructions[key])) {
      target[key] = instructions[key];
      continue;
    }
    applyInstruction(target, null, instructions, key);
  }
  return target;
}
var mapWithFilter = (target, filter, instructions) => {
  return map(target, Object.entries(instructions).reduce((_instructions, [key, value]) => {
    if (Array.isArray(value)) {
      _instructions[key] = value;
    } else {
      if (typeof value === "function") {
        _instructions[key] = [filter, value()];
      } else {
        _instructions[key] = [filter, value];
      }
    }
    return _instructions;
  }, {}));
};
var applyInstruction = (target, source, instructions, targetKey) => {
  if (source !== null) {
    let instruction = instructions[targetKey];
    if (typeof instruction === "function") {
      instruction = [, instruction];
    }
    const [filter2 = nonNullish, valueFn = pass, sourceKey = targetKey] = instruction;
    if (typeof filter2 === "function" && filter2(source[sourceKey]) || typeof filter2 !== "function" && !!filter2) {
      target[targetKey] = valueFn(source[sourceKey]);
    }
    return;
  }
  let [filter, value] = instructions[targetKey];
  if (typeof value === "function") {
    let _value;
    const defaultFilterPassed = filter === void 0 && (_value = value()) != null;
    const customFilterPassed = typeof filter === "function" && !!filter(void 0) || typeof filter !== "function" && !!filter;
    if (defaultFilterPassed) {
      target[targetKey] = _value;
    } else if (customFilterPassed) {
      target[targetKey] = value();
    }
  } else {
    const defaultFilterPassed = filter === void 0 && value != null;
    const customFilterPassed = typeof filter === "function" && !!filter(value) || typeof filter !== "function" && !!filter;
    if (defaultFilterPassed || customFilterPassed) {
      target[targetKey] = value;
    }
  }
};
var nonNullish = (_) => _ != null;
var pass = (_) => _;

// node_modules/@smithy/smithy-client/dist-es/ser-utils.js
var serializeDateTime = (date) => date.toISOString().replace(".000Z", "Z");

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js
init_dist_es();
var collectBodyString = (streamBody, context) => collectBody(streamBody, context).then((body) => (context?.utf8Encoder ?? toUtf8)(body));

// node_modules/@aws-sdk/xml-builder/dist-es/xml-parser.browser.js
var parser;
function parseXML(xmlString) {
  if (!parser) {
    parser = new DOMParser();
  }
  const xmlDocument = parser.parseFromString(xmlString, "application/xml");
  if (xmlDocument.getElementsByTagName("parsererror").length > 0) {
    throw new Error("DOMParser XML parsing error.");
  }
  const xmlToObj = (node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      if (node.textContent?.trim()) {
        return node.textContent;
      }
    }
    if (node.nodeType === Node.ELEMENT_NODE) {
      const element = node;
      if (element.attributes.length === 0 && element.childNodes.length === 0) {
        return "";
      }
      const obj = {};
      const attributes = Array.from(element.attributes);
      for (const attr of attributes) {
        obj[`${attr.name}`] = attr.value;
      }
      const childNodes = Array.from(element.childNodes);
      for (const child of childNodes) {
        const childResult = xmlToObj(child);
        if (childResult != null) {
          const childName = child.nodeName;
          if (childNodes.length === 1 && attributes.length === 0 && childName === "#text") {
            return childResult;
          }
          if (obj[childName]) {
            if (Array.isArray(obj[childName])) {
              obj[childName].push(childResult);
            } else {
              obj[childName] = [obj[childName], childResult];
            }
          } else {
            obj[childName] = childResult;
          }
        } else if (childNodes.length === 1 && attributes.length === 0) {
          return element.textContent;
        }
      }
      return obj;
    }
    return null;
  };
  return {
    [xmlDocument.documentElement.nodeName]: xmlToObj(xmlDocument.documentElement)
  };
}

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/parseXmlBody.js
var parseXmlBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
  if (encoded.length) {
    let parsedObj;
    try {
      parsedObj = parseXML(encoded);
    } catch (e2) {
      if (e2 && typeof e2 === "object") {
        Object.defineProperty(e2, "$responseBodyText", {
          value: encoded
        });
      }
      throw e2;
    }
    const textNodeName = "#text";
    const key = Object.keys(parsedObj)[0];
    const parsedObjToReturn = parsedObj[key];
    if (parsedObjToReturn[textNodeName]) {
      parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
      delete parsedObjToReturn[textNodeName];
    }
    return getValueFromTextNode(parsedObjToReturn);
  }
  return {};
});
var parseXmlErrorBody = async (errorBody, context) => {
  const value = await parseXmlBody(errorBody, context);
  if (value.Error) {
    value.Error.message = value.Error.message ?? value.Error.Message;
  }
  return value;
};
var loadRestXmlErrorCode = (output, data) => {
  if (data?.Error?.Code !== void 0) {
    return data.Error.Code;
  }
  if (data?.Code !== void 0) {
    return data.Code;
  }
  if (output.statusCode == 404) {
    return "NotFound";
  }
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/types.js
var CLIENT_SUPPORTED_ALGORITHMS = [
  ChecksumAlgorithm.CRC32,
  ChecksumAlgorithm.CRC32C,
  ChecksumAlgorithm.CRC64NVME,
  ChecksumAlgorithm.SHA1,
  ChecksumAlgorithm.SHA256
];
var PRIORITY_ORDER_ALGORITHMS = [
  ChecksumAlgorithm.SHA256,
  ChecksumAlgorithm.SHA1,
  ChecksumAlgorithm.CRC32,
  ChecksumAlgorithm.CRC32C,
  ChecksumAlgorithm.CRC64NVME
];

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/getChecksumAlgorithmForRequest.js
var getChecksumAlgorithmForRequest = (input, { requestChecksumRequired, requestAlgorithmMember, requestChecksumCalculation }) => {
  if (!requestAlgorithmMember) {
    return requestChecksumCalculation === RequestChecksumCalculation.WHEN_SUPPORTED || requestChecksumRequired ? DEFAULT_CHECKSUM_ALGORITHM : void 0;
  }
  if (!input[requestAlgorithmMember]) {
    return void 0;
  }
  const checksumAlgorithm = input[requestAlgorithmMember];
  if (!CLIENT_SUPPORTED_ALGORITHMS.includes(checksumAlgorithm)) {
    throw new Error(`The checksum algorithm "${checksumAlgorithm}" is not supported by the client. Select one of ${CLIENT_SUPPORTED_ALGORITHMS}.`);
  }
  return checksumAlgorithm;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/getChecksumLocationName.js
var getChecksumLocationName = (algorithm) => algorithm === ChecksumAlgorithm.MD5 ? "content-md5" : `x-amz-checksum-${algorithm.toLowerCase()}`;

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/hasHeader.js
var hasHeader2 = (header, headers) => {
  const soughtHeader = header.toLowerCase();
  for (const headerName of Object.keys(headers)) {
    if (soughtHeader === headerName.toLowerCase()) {
      return true;
    }
  }
  return false;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/hasHeaderWithPrefix.js
var hasHeaderWithPrefix = (headerPrefix, headers) => {
  const soughtHeaderPrefix = headerPrefix.toLowerCase();
  for (const headerName of Object.keys(headers)) {
    if (headerName.toLowerCase().startsWith(soughtHeaderPrefix)) {
      return true;
    }
  }
  return false;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/isStreaming.js
var isStreaming = (body) => body !== void 0 && typeof body !== "string" && !ArrayBuffer.isView(body) && !isArrayBuffer(body);

// node_modules/tslib/tslib.es6.mjs
function __awaiter(thisArg, _arguments, P2, generator) {
  function adopt(value) {
    return value instanceof P2 ? value : new P2(function(resolve) {
      resolve(value);
    });
  }
  return new (P2 || (P2 = Promise))(function(resolve, reject) {
    function fulfilled(value) {
      try {
        step(generator.next(value));
      } catch (e2) {
        reject(e2);
      }
    }
    function rejected(value) {
      try {
        step(generator["throw"](value));
      } catch (e2) {
        reject(e2);
      }
    }
    function step(result) {
      result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
    }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
}
function __generator(thisArg, body) {
  var _ = { label: 0, sent: function() {
    if (t2[0] & 1) throw t2[1];
    return t2[1];
  }, trys: [], ops: [] }, f2, y2, t2, g2 = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
  return g2.next = verb(0), g2["throw"] = verb(1), g2["return"] = verb(2), typeof Symbol === "function" && (g2[Symbol.iterator] = function() {
    return this;
  }), g2;
  function verb(n2) {
    return function(v2) {
      return step([n2, v2]);
    };
  }
  function step(op) {
    if (f2) throw new TypeError("Generator is already executing.");
    while (g2 && (g2 = 0, op[0] && (_ = 0)), _) try {
      if (f2 = 1, y2 && (t2 = op[0] & 2 ? y2["return"] : op[0] ? y2["throw"] || ((t2 = y2["return"]) && t2.call(y2), 0) : y2.next) && !(t2 = t2.call(y2, op[1])).done) return t2;
      if (y2 = 0, t2) op = [op[0] & 2, t2.value];
      switch (op[0]) {
        case 0:
        case 1:
          t2 = op;
          break;
        case 4:
          _.label++;
          return { value: op[1], done: false };
        case 5:
          _.label++;
          y2 = op[1];
          op = [0];
          continue;
        case 7:
          op = _.ops.pop();
          _.trys.pop();
          continue;
        default:
          if (!(t2 = _.trys, t2 = t2.length > 0 && t2[t2.length - 1]) && (op[0] === 6 || op[0] === 2)) {
            _ = 0;
            continue;
          }
          if (op[0] === 3 && (!t2 || op[1] > t2[0] && op[1] < t2[3])) {
            _.label = op[1];
            break;
          }
          if (op[0] === 6 && _.label < t2[1]) {
            _.label = t2[1];
            t2 = op;
            break;
          }
          if (t2 && _.label < t2[2]) {
            _.label = t2[2];
            _.ops.push(op);
            break;
          }
          if (t2[2]) _.ops.pop();
          _.trys.pop();
          continue;
      }
      op = body.call(thisArg, _);
    } catch (e2) {
      op = [6, e2];
      y2 = 0;
    } finally {
      f2 = t2 = 0;
    }
    if (op[0] & 5) throw op[1];
    return { value: op[0] ? op[1] : void 0, done: true };
  }
}
function __values(o2) {
  var s2 = typeof Symbol === "function" && Symbol.iterator, m2 = s2 && o2[s2], i2 = 0;
  if (m2) return m2.call(o2);
  if (o2 && typeof o2.length === "number") return {
    next: function() {
      if (o2 && i2 >= o2.length) o2 = void 0;
      return { value: o2 && o2[i2++], done: !o2 };
    }
  };
  throw new TypeError(s2 ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

// node_modules/@aws-crypto/util/node_modules/@smithy/util-utf8/dist-es/fromUtf8.browser.js
var fromUtf82 = (input) => new TextEncoder().encode(input);

// node_modules/@aws-crypto/util/build/module/convertToBuffer.js
var fromUtf83 = typeof Buffer !== "undefined" && Buffer.from ? function(input) {
  return Buffer.from(input, "utf8");
} : fromUtf82;
function convertToBuffer(data) {
  if (data instanceof Uint8Array)
    return data;
  if (typeof data === "string") {
    return fromUtf83(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
  }
  return new Uint8Array(data);
}

// node_modules/@aws-crypto/util/build/module/isEmptyData.js
function isEmptyData(data) {
  if (typeof data === "string") {
    return data.length === 0;
  }
  return data.byteLength === 0;
}

// node_modules/@aws-crypto/util/build/module/numToUint8.js
function numToUint8(num) {
  return new Uint8Array([
    (num & 4278190080) >> 24,
    (num & 16711680) >> 16,
    (num & 65280) >> 8,
    num & 255
  ]);
}

// node_modules/@aws-crypto/util/build/module/uint32ArrayFrom.js
function uint32ArrayFrom(a_lookUpTable2) {
  if (!Uint32Array.from) {
    var return_array = new Uint32Array(a_lookUpTable2.length);
    var a_index = 0;
    while (a_index < a_lookUpTable2.length) {
      return_array[a_index] = a_lookUpTable2[a_index];
      a_index += 1;
    }
    return return_array;
  }
  return Uint32Array.from(a_lookUpTable2);
}

// node_modules/@aws-crypto/crc32c/build/module/aws_crc32c.js
var AwsCrc32c = (
  /** @class */
  (function() {
    function AwsCrc32c2() {
      this.crc32c = new Crc32c();
    }
    AwsCrc32c2.prototype.update = function(toHash) {
      if (isEmptyData(toHash))
        return;
      this.crc32c.update(convertToBuffer(toHash));
    };
    AwsCrc32c2.prototype.digest = function() {
      return __awaiter(this, void 0, void 0, function() {
        return __generator(this, function(_a) {
          return [2, numToUint8(this.crc32c.digest())];
        });
      });
    };
    AwsCrc32c2.prototype.reset = function() {
      this.crc32c = new Crc32c();
    };
    return AwsCrc32c2;
  })()
);

// node_modules/@aws-crypto/crc32c/build/module/index.js
var Crc32c = (
  /** @class */
  (function() {
    function Crc32c2() {
      this.checksum = 4294967295;
    }
    Crc32c2.prototype.update = function(data) {
      var e_1, _a;
      try {
        for (var data_1 = __values(data), data_1_1 = data_1.next(); !data_1_1.done; data_1_1 = data_1.next()) {
          var byte = data_1_1.value;
          this.checksum = this.checksum >>> 8 ^ lookupTable[(this.checksum ^ byte) & 255];
        }
      } catch (e_1_1) {
        e_1 = { error: e_1_1 };
      } finally {
        try {
          if (data_1_1 && !data_1_1.done && (_a = data_1.return)) _a.call(data_1);
        } finally {
          if (e_1) throw e_1.error;
        }
      }
      return this;
    };
    Crc32c2.prototype.digest = function() {
      return (this.checksum ^ 4294967295) >>> 0;
    };
    return Crc32c2;
  })()
);
var a_lookupTable = [
  0,
  4067132163,
  3778769143,
  324072436,
  3348797215,
  904991772,
  648144872,
  3570033899,
  2329499855,
  2024987596,
  1809983544,
  2575936315,
  1296289744,
  3207089363,
  2893594407,
  1578318884,
  274646895,
  3795141740,
  4049975192,
  51262619,
  3619967088,
  632279923,
  922689671,
  3298075524,
  2592579488,
  1760304291,
  2075979607,
  2312596564,
  1562183871,
  2943781820,
  3156637768,
  1313733451,
  549293790,
  3537243613,
  3246849577,
  871202090,
  3878099393,
  357341890,
  102525238,
  4101499445,
  2858735121,
  1477399826,
  1264559846,
  3107202533,
  1845379342,
  2677391885,
  2361733625,
  2125378298,
  820201905,
  3263744690,
  3520608582,
  598981189,
  4151959214,
  85089709,
  373468761,
  3827903834,
  3124367742,
  1213305469,
  1526817161,
  2842354314,
  2107672161,
  2412447074,
  2627466902,
  1861252501,
  1098587580,
  3004210879,
  2688576843,
  1378610760,
  2262928035,
  1955203488,
  1742404180,
  2511436119,
  3416409459,
  969524848,
  714683780,
  3639785095,
  205050476,
  4266873199,
  3976438427,
  526918040,
  1361435347,
  2739821008,
  2954799652,
  1114974503,
  2529119692,
  1691668175,
  2005155131,
  2247081528,
  3690758684,
  697762079,
  986182379,
  3366744552,
  476452099,
  3993867776,
  4250756596,
  255256311,
  1640403810,
  2477592673,
  2164122517,
  1922457750,
  2791048317,
  1412925310,
  1197962378,
  3037525897,
  3944729517,
  427051182,
  170179418,
  4165941337,
  746937522,
  3740196785,
  3451792453,
  1070968646,
  1905808397,
  2213795598,
  2426610938,
  1657317369,
  3053634322,
  1147748369,
  1463399397,
  2773627110,
  4215344322,
  153784257,
  444234805,
  3893493558,
  1021025245,
  3467647198,
  3722505002,
  797665321,
  2197175160,
  1889384571,
  1674398607,
  2443626636,
  1164749927,
  3070701412,
  2757221520,
  1446797203,
  137323447,
  4198817972,
  3910406976,
  461344835,
  3484808360,
  1037989803,
  781091935,
  3705997148,
  2460548119,
  1623424788,
  1939049696,
  2180517859,
  1429367560,
  2807687179,
  3020495871,
  1180866812,
  410100952,
  3927582683,
  4182430767,
  186734380,
  3756733383,
  763408580,
  1053836080,
  3434856499,
  2722870694,
  1344288421,
  1131464017,
  2971354706,
  1708204729,
  2545590714,
  2229949006,
  1988219213,
  680717673,
  3673779818,
  3383336350,
  1002577565,
  4010310262,
  493091189,
  238226049,
  4233660802,
  2987750089,
  1082061258,
  1395524158,
  2705686845,
  1972364758,
  2279892693,
  2494862625,
  1725896226,
  952904198,
  3399985413,
  3656866545,
  731699698,
  4283874585,
  222117402,
  510512622,
  3959836397,
  3280807620,
  837199303,
  582374963,
  3504198960,
  68661723,
  4135334616,
  3844915500,
  390545967,
  1230274059,
  3141532936,
  2825850620,
  1510247935,
  2395924756,
  2091215383,
  1878366691,
  2644384480,
  3553878443,
  565732008,
  854102364,
  3229815391,
  340358836,
  3861050807,
  4117890627,
  119113024,
  1493875044,
  2875275879,
  3090270611,
  1247431312,
  2660249211,
  1828433272,
  2141937292,
  2378227087,
  3811616794,
  291187481,
  34330861,
  4032846830,
  615137029,
  3603020806,
  3314634738,
  939183345,
  1776939221,
  2609017814,
  2295496738,
  2058945313,
  2926798794,
  1545135305,
  1330124605,
  3173225534,
  4084100981,
  17165430,
  307568514,
  3762199681,
  888469610,
  3332340585,
  3587147933,
  665062302,
  2042050490,
  2346497209,
  2559330125,
  1793573966,
  3190661285,
  1279665062,
  1595330642,
  2910671697
];
var lookupTable = uint32ArrayFrom(a_lookupTable);

// node_modules/@aws-crypto/crc32/build/module/aws_crc32.js
var AwsCrc32 = (
  /** @class */
  (function() {
    function AwsCrc322() {
      this.crc32 = new Crc32();
    }
    AwsCrc322.prototype.update = function(toHash) {
      if (isEmptyData(toHash))
        return;
      this.crc32.update(convertToBuffer(toHash));
    };
    AwsCrc322.prototype.digest = function() {
      return __awaiter(this, void 0, void 0, function() {
        return __generator(this, function(_a) {
          return [2, numToUint8(this.crc32.digest())];
        });
      });
    };
    AwsCrc322.prototype.reset = function() {
      this.crc32 = new Crc32();
    };
    return AwsCrc322;
  })()
);

// node_modules/@aws-crypto/crc32/build/module/index.js
var Crc32 = (
  /** @class */
  (function() {
    function Crc322() {
      this.checksum = 4294967295;
    }
    Crc322.prototype.update = function(data) {
      var e_1, _a;
      try {
        for (var data_1 = __values(data), data_1_1 = data_1.next(); !data_1_1.done; data_1_1 = data_1.next()) {
          var byte = data_1_1.value;
          this.checksum = this.checksum >>> 8 ^ lookupTable2[(this.checksum ^ byte) & 255];
        }
      } catch (e_1_1) {
        e_1 = { error: e_1_1 };
      } finally {
        try {
          if (data_1_1 && !data_1_1.done && (_a = data_1.return)) _a.call(data_1);
        } finally {
          if (e_1) throw e_1.error;
        }
      }
      return this;
    };
    Crc322.prototype.digest = function() {
      return (this.checksum ^ 4294967295) >>> 0;
    };
    return Crc322;
  })()
);
var a_lookUpTable = [
  0,
  1996959894,
  3993919788,
  2567524794,
  124634137,
  1886057615,
  3915621685,
  2657392035,
  249268274,
  2044508324,
  3772115230,
  2547177864,
  162941995,
  2125561021,
  3887607047,
  2428444049,
  498536548,
  1789927666,
  4089016648,
  2227061214,
  450548861,
  1843258603,
  4107580753,
  2211677639,
  325883990,
  1684777152,
  4251122042,
  2321926636,
  335633487,
  1661365465,
  4195302755,
  2366115317,
  997073096,
  1281953886,
  3579855332,
  2724688242,
  1006888145,
  1258607687,
  3524101629,
  2768942443,
  901097722,
  1119000684,
  3686517206,
  2898065728,
  853044451,
  1172266101,
  3705015759,
  2882616665,
  651767980,
  1373503546,
  3369554304,
  3218104598,
  565507253,
  1454621731,
  3485111705,
  3099436303,
  671266974,
  1594198024,
  3322730930,
  2970347812,
  795835527,
  1483230225,
  3244367275,
  3060149565,
  1994146192,
  31158534,
  2563907772,
  4023717930,
  1907459465,
  112637215,
  2680153253,
  3904427059,
  2013776290,
  251722036,
  2517215374,
  3775830040,
  2137656763,
  141376813,
  2439277719,
  3865271297,
  1802195444,
  476864866,
  2238001368,
  4066508878,
  1812370925,
  453092731,
  2181625025,
  4111451223,
  1706088902,
  314042704,
  2344532202,
  4240017532,
  1658658271,
  366619977,
  2362670323,
  4224994405,
  1303535960,
  984961486,
  2747007092,
  3569037538,
  1256170817,
  1037604311,
  2765210733,
  3554079995,
  1131014506,
  879679996,
  2909243462,
  3663771856,
  1141124467,
  855842277,
  2852801631,
  3708648649,
  1342533948,
  654459306,
  3188396048,
  3373015174,
  1466479909,
  544179635,
  3110523913,
  3462522015,
  1591671054,
  702138776,
  2966460450,
  3352799412,
  1504918807,
  783551873,
  3082640443,
  3233442989,
  3988292384,
  2596254646,
  62317068,
  1957810842,
  3939845945,
  2647816111,
  81470997,
  1943803523,
  3814918930,
  2489596804,
  225274430,
  2053790376,
  3826175755,
  2466906013,
  167816743,
  2097651377,
  4027552580,
  2265490386,
  503444072,
  1762050814,
  4150417245,
  2154129355,
  426522225,
  1852507879,
  4275313526,
  2312317920,
  282753626,
  1742555852,
  4189708143,
  2394877945,
  397917763,
  1622183637,
  3604390888,
  2714866558,
  953729732,
  1340076626,
  3518719985,
  2797360999,
  1068828381,
  1219638859,
  3624741850,
  2936675148,
  906185462,
  1090812512,
  3747672003,
  2825379669,
  829329135,
  1181335161,
  3412177804,
  3160834842,
  628085408,
  1382605366,
  3423369109,
  3138078467,
  570562233,
  1426400815,
  3317316542,
  2998733608,
  733239954,
  1555261956,
  3268935591,
  3050360625,
  752459403,
  1541320221,
  2607071920,
  3965973030,
  1969922972,
  40735498,
  2617837225,
  3943577151,
  1913087877,
  83908371,
  2512341634,
  3803740692,
  2075208622,
  213261112,
  2463272603,
  3855990285,
  2094854071,
  198958881,
  2262029012,
  4057260610,
  1759359992,
  534414190,
  2176718541,
  4139329115,
  1873836001,
  414664567,
  2282248934,
  4279200368,
  1711684554,
  285281116,
  2405801727,
  4167216745,
  1634467795,
  376229701,
  2685067896,
  3608007406,
  1308918612,
  956543938,
  2808555105,
  3495958263,
  1231636301,
  1047427035,
  2932959818,
  3654703836,
  1088359270,
  936918e3,
  2847714899,
  3736837829,
  1202900863,
  817233897,
  3183342108,
  3401237130,
  1404277552,
  615818150,
  3134207493,
  3453421203,
  1423857449,
  601450431,
  3009837614,
  3294710456,
  1567103746,
  711928724,
  3020668471,
  3272380065,
  1510334235,
  755167117
];
var lookupTable2 = uint32ArrayFrom(a_lookUpTable);

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/getCrc32ChecksumAlgorithmFunction.browser.js
var getCrc32ChecksumAlgorithmFunction = () => AwsCrc32;

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/selectChecksumAlgorithmFunction.js
var selectChecksumAlgorithmFunction = (checksumAlgorithm, config) => {
  switch (checksumAlgorithm) {
    case ChecksumAlgorithm.MD5:
      return config.md5;
    case ChecksumAlgorithm.CRC32:
      return getCrc32ChecksumAlgorithmFunction();
    case ChecksumAlgorithm.CRC32C:
      return AwsCrc32c;
    case ChecksumAlgorithm.CRC64NVME:
      if (typeof crc64NvmeCrtContainer.CrtCrc64Nvme !== "function") {
        throw new Error(`Please check whether you have installed the "@aws-sdk/crc64-nvme-crt" package explicitly. 
You must also register the package by calling [require("@aws-sdk/crc64-nvme-crt");] or an ESM equivalent such as [import "@aws-sdk/crc64-nvme-crt";]. 
For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt`);
      }
      return crc64NvmeCrtContainer.CrtCrc64Nvme;
    case ChecksumAlgorithm.SHA1:
      return config.sha1;
    case ChecksumAlgorithm.SHA256:
      return config.sha256;
    default:
      throw new Error(`Unsupported checksum algorithm: ${checksumAlgorithm}`);
  }
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/stringHasher.js
init_dist_es();
var stringHasher = (checksumAlgorithmFn, body) => {
  const hash = new checksumAlgorithmFn();
  hash.update(toUint8Array(body || ""));
  return hash.digest();
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/flexibleChecksumsMiddleware.js
var flexibleChecksumsMiddlewareOptions = {
  name: "flexibleChecksumsMiddleware",
  step: "build",
  tags: ["BODY_CHECKSUM"],
  override: true
};
var flexibleChecksumsMiddleware = (config, middlewareConfig) => (next, context) => async (args) => {
  if (!HttpRequest.isInstance(args.request)) {
    return next(args);
  }
  if (hasHeaderWithPrefix("x-amz-checksum-", args.request.headers)) {
    return next(args);
  }
  const { request, input } = args;
  const { body: requestBody, headers } = request;
  const { base64Encoder, streamHasher } = config;
  const { requestChecksumRequired, requestAlgorithmMember } = middlewareConfig;
  const requestChecksumCalculation = await config.requestChecksumCalculation();
  const requestAlgorithmMemberName = requestAlgorithmMember?.name;
  const requestAlgorithmMemberHttpHeader = requestAlgorithmMember?.httpHeader;
  if (requestAlgorithmMemberName && !input[requestAlgorithmMemberName]) {
    if (requestChecksumCalculation === RequestChecksumCalculation.WHEN_SUPPORTED || requestChecksumRequired) {
      input[requestAlgorithmMemberName] = DEFAULT_CHECKSUM_ALGORITHM;
      if (requestAlgorithmMemberHttpHeader) {
        headers[requestAlgorithmMemberHttpHeader] = DEFAULT_CHECKSUM_ALGORITHM;
      }
    }
  }
  const checksumAlgorithm = getChecksumAlgorithmForRequest(input, {
    requestChecksumRequired,
    requestAlgorithmMember: requestAlgorithmMember?.name,
    requestChecksumCalculation
  });
  let updatedBody = requestBody;
  let updatedHeaders = headers;
  if (checksumAlgorithm) {
    switch (checksumAlgorithm) {
      case ChecksumAlgorithm.CRC32:
        setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_CRC32", "U");
        break;
      case ChecksumAlgorithm.CRC32C:
        setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_CRC32C", "V");
        break;
      case ChecksumAlgorithm.CRC64NVME:
        setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_CRC64", "W");
        break;
      case ChecksumAlgorithm.SHA1:
        setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_SHA1", "X");
        break;
      case ChecksumAlgorithm.SHA256:
        setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_SHA256", "Y");
        break;
    }
    const checksumLocationName = getChecksumLocationName(checksumAlgorithm);
    const checksumAlgorithmFn = selectChecksumAlgorithmFunction(checksumAlgorithm, config);
    if (isStreaming(requestBody)) {
      const { getAwsChunkedEncodingStream: getAwsChunkedEncodingStream2, bodyLengthChecker } = config;
      updatedBody = getAwsChunkedEncodingStream2(typeof config.requestStreamBufferSize === "number" && config.requestStreamBufferSize >= 8 * 1024 ? createBufferedReadable(requestBody, config.requestStreamBufferSize, context.logger) : requestBody, {
        base64Encoder,
        bodyLengthChecker,
        checksumLocationName,
        checksumAlgorithmFn,
        streamHasher
      });
      updatedHeaders = {
        ...headers,
        "content-encoding": headers["content-encoding"] ? `${headers["content-encoding"]},aws-chunked` : "aws-chunked",
        "transfer-encoding": "chunked",
        "x-amz-decoded-content-length": headers["content-length"],
        "x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "x-amz-trailer": checksumLocationName
      };
      delete updatedHeaders["content-length"];
    } else if (!hasHeader2(checksumLocationName, headers)) {
      const rawChecksum = await stringHasher(checksumAlgorithmFn, requestBody);
      updatedHeaders = {
        ...headers,
        [checksumLocationName]: base64Encoder(rawChecksum)
      };
    }
  }
  const result = await next({
    ...args,
    request: {
      ...request,
      headers: updatedHeaders,
      body: updatedBody
    }
  });
  return result;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/flexibleChecksumsInputMiddleware.js
var flexibleChecksumsInputMiddlewareOptions = {
  name: "flexibleChecksumsInputMiddleware",
  toMiddleware: "serializerMiddleware",
  relation: "before",
  tags: ["BODY_CHECKSUM"],
  override: true
};
var flexibleChecksumsInputMiddleware = (config, middlewareConfig) => (next, context) => async (args) => {
  const input = args.input;
  const { requestValidationModeMember } = middlewareConfig;
  const requestChecksumCalculation = await config.requestChecksumCalculation();
  const responseChecksumValidation = await config.responseChecksumValidation();
  switch (requestChecksumCalculation) {
    case RequestChecksumCalculation.WHEN_REQUIRED:
      setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_WHEN_REQUIRED", "a");
      break;
    case RequestChecksumCalculation.WHEN_SUPPORTED:
      setFeature(context, "FLEXIBLE_CHECKSUMS_REQ_WHEN_SUPPORTED", "Z");
      break;
  }
  switch (responseChecksumValidation) {
    case ResponseChecksumValidation.WHEN_REQUIRED:
      setFeature(context, "FLEXIBLE_CHECKSUMS_RES_WHEN_REQUIRED", "c");
      break;
    case ResponseChecksumValidation.WHEN_SUPPORTED:
      setFeature(context, "FLEXIBLE_CHECKSUMS_RES_WHEN_SUPPORTED", "b");
      break;
  }
  if (requestValidationModeMember && !input[requestValidationModeMember]) {
    if (responseChecksumValidation === ResponseChecksumValidation.WHEN_SUPPORTED) {
      input[requestValidationModeMember] = "ENABLED";
    }
  }
  return next(args);
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/getChecksumAlgorithmListForResponse.js
var getChecksumAlgorithmListForResponse = (responseAlgorithms = []) => {
  const validChecksumAlgorithms = [];
  for (const algorithm of PRIORITY_ORDER_ALGORITHMS) {
    if (!responseAlgorithms.includes(algorithm) || !CLIENT_SUPPORTED_ALGORITHMS.includes(algorithm)) {
      continue;
    }
    validChecksumAlgorithms.push(algorithm);
  }
  return validChecksumAlgorithms;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/isChecksumWithPartNumber.js
var isChecksumWithPartNumber = (checksum) => {
  const lastHyphenIndex = checksum.lastIndexOf("-");
  if (lastHyphenIndex !== -1) {
    const numberPart = checksum.slice(lastHyphenIndex + 1);
    if (!numberPart.startsWith("0")) {
      const number = parseInt(numberPart, 10);
      if (!isNaN(number) && number >= 1 && number <= 1e4) {
        return true;
      }
    }
  }
  return false;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/getChecksum.js
var getChecksum = async (body, { checksumAlgorithmFn, base64Encoder }) => base64Encoder(await stringHasher(checksumAlgorithmFn, body));

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/validateChecksumFromResponse.js
var validateChecksumFromResponse = async (response, { config, responseAlgorithms, logger: logger2 }) => {
  const checksumAlgorithms = getChecksumAlgorithmListForResponse(responseAlgorithms);
  const { body: responseBody, headers: responseHeaders } = response;
  for (const algorithm of checksumAlgorithms) {
    const responseHeader = getChecksumLocationName(algorithm);
    const checksumFromResponse = responseHeaders[responseHeader];
    if (checksumFromResponse) {
      let checksumAlgorithmFn;
      try {
        checksumAlgorithmFn = selectChecksumAlgorithmFunction(algorithm, config);
      } catch (error) {
        if (algorithm === ChecksumAlgorithm.CRC64NVME) {
          logger2?.warn(`Skipping ${ChecksumAlgorithm.CRC64NVME} checksum validation: ${error.message}`);
          continue;
        }
        throw error;
      }
      const { base64Encoder } = config;
      if (isStreaming(responseBody)) {
        response.body = createChecksumStream({
          expectedChecksum: checksumFromResponse,
          checksumSourceLocation: responseHeader,
          checksum: new checksumAlgorithmFn(),
          source: responseBody,
          base64Encoder
        });
        return;
      }
      const checksum = await getChecksum(responseBody, { checksumAlgorithmFn, base64Encoder });
      if (checksum === checksumFromResponse) {
        break;
      }
      throw new Error(`Checksum mismatch: expected "${checksum}" but received "${checksumFromResponse}" in response header "${responseHeader}".`);
    }
  }
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/flexibleChecksumsResponseMiddleware.js
var flexibleChecksumsResponseMiddlewareOptions = {
  name: "flexibleChecksumsResponseMiddleware",
  toMiddleware: "deserializerMiddleware",
  relation: "after",
  tags: ["BODY_CHECKSUM"],
  override: true
};
var flexibleChecksumsResponseMiddleware = (config, middlewareConfig) => (next, context) => async (args) => {
  if (!HttpRequest.isInstance(args.request)) {
    return next(args);
  }
  const input = args.input;
  const result = await next(args);
  const response = result.response;
  const { requestValidationModeMember, responseAlgorithms } = middlewareConfig;
  if (requestValidationModeMember && input[requestValidationModeMember] === "ENABLED") {
    const { clientName, commandName } = context;
    const isS3WholeObjectMultipartGetResponseChecksum = clientName === "S3Client" && commandName === "GetObjectCommand" && getChecksumAlgorithmListForResponse(responseAlgorithms).every((algorithm) => {
      const responseHeader = getChecksumLocationName(algorithm);
      const checksumFromResponse = response.headers[responseHeader];
      return !checksumFromResponse || isChecksumWithPartNumber(checksumFromResponse);
    });
    if (isS3WholeObjectMultipartGetResponseChecksum) {
      return result;
    }
    await validateChecksumFromResponse(response, {
      config,
      responseAlgorithms,
      logger: context.logger
    });
  }
  return result;
};

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/getFlexibleChecksumsPlugin.js
var getFlexibleChecksumsPlugin = (config, middlewareConfig) => ({
  applyToStack: (clientStack) => {
    clientStack.add(flexibleChecksumsMiddleware(config, middlewareConfig), flexibleChecksumsMiddlewareOptions);
    clientStack.addRelativeTo(flexibleChecksumsInputMiddleware(config, middlewareConfig), flexibleChecksumsInputMiddlewareOptions);
    clientStack.addRelativeTo(flexibleChecksumsResponseMiddleware(config, middlewareConfig), flexibleChecksumsResponseMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-flexible-checksums/dist-es/resolveFlexibleChecksumsConfig.js
var resolveFlexibleChecksumsConfig = (input) => {
  const { requestChecksumCalculation, responseChecksumValidation, requestStreamBufferSize } = input;
  return Object.assign(input, {
    requestChecksumCalculation: normalizeProvider(requestChecksumCalculation ?? DEFAULT_REQUEST_CHECKSUM_CALCULATION),
    responseChecksumValidation: normalizeProvider(responseChecksumValidation ?? DEFAULT_RESPONSE_CHECKSUM_VALIDATION),
    requestStreamBufferSize: Number(requestStreamBufferSize ?? 0)
  });
};

// node_modules/@aws-sdk/middleware-host-header/dist-es/index.js
function resolveHostHeaderConfig(input) {
  return input;
}
var hostHeaderMiddleware = (options) => (next) => async (args) => {
  if (!HttpRequest.isInstance(args.request))
    return next(args);
  const { request } = args;
  const { handlerProtocol = "" } = options.requestHandler.metadata || {};
  if (handlerProtocol.indexOf("h2") >= 0 && !request.headers[":authority"]) {
    delete request.headers["host"];
    request.headers[":authority"] = request.hostname + (request.port ? ":" + request.port : "");
  } else if (!request.headers["host"]) {
    let host = request.hostname;
    if (request.port != null)
      host += `:${request.port}`;
    request.headers["host"] = host;
  }
  return next(args);
};
var hostHeaderMiddlewareOptions = {
  name: "hostHeaderMiddleware",
  step: "build",
  priority: "low",
  tags: ["HOST"],
  override: true
};
var getHostHeaderPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-logger/dist-es/loggerMiddleware.js
var loggerMiddleware = () => (next, context) => async (args) => {
  try {
    const response = await next(args);
    const { clientName, commandName, logger: logger2, dynamoDbDocumentClientOptions = {} } = context;
    const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
    const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
    const { $metadata, ...outputWithoutMetadata } = response.output;
    logger2?.info?.({
      clientName,
      commandName,
      input: inputFilterSensitiveLog(args.input),
      output: outputFilterSensitiveLog(outputWithoutMetadata),
      metadata: $metadata
    });
    return response;
  } catch (error) {
    const { clientName, commandName, logger: logger2, dynamoDbDocumentClientOptions = {} } = context;
    const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
    logger2?.error?.({
      clientName,
      commandName,
      input: inputFilterSensitiveLog(args.input),
      error,
      metadata: error.$metadata
    });
    throw error;
  }
};
var loggerMiddlewareOptions = {
  name: "loggerMiddleware",
  tags: ["LOGGER"],
  step: "initialize",
  override: true
};
var getLoggerPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/configuration.js
var recursionDetectionMiddlewareOptions = {
  step: "build",
  tags: ["RECURSION_DETECTION"],
  name: "recursionDetectionMiddleware",
  override: true,
  priority: "low"
};

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/recursionDetectionMiddleware.browser.js
var recursionDetectionMiddleware = () => (next) => async (args) => next(args);

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/getRecursionDetectionPlugin.js
var getRecursionDetectionPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(recursionDetectionMiddleware(), recursionDetectionMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/check-content-length-header.js
var CONTENT_LENGTH_HEADER = "content-length";
var DECODED_CONTENT_LENGTH_HEADER = "x-amz-decoded-content-length";
function checkContentLengthHeader() {
  return (next, context) => async (args) => {
    const { request } = args;
    if (HttpRequest.isInstance(request)) {
      if (!(CONTENT_LENGTH_HEADER in request.headers) && !(DECODED_CONTENT_LENGTH_HEADER in request.headers)) {
        const message = `Are you using a Stream of unknown length as the Body of a PutObject request? Consider using Upload instead from @aws-sdk/lib-storage.`;
        if (typeof context?.logger?.warn === "function" && !(context.logger instanceof NoOpLogger)) {
          context.logger.warn(message);
        } else {
          console.warn(message);
        }
      }
    }
    return next({ ...args });
  };
}
var checkContentLengthHeaderMiddlewareOptions = {
  step: "finalizeRequest",
  tags: ["CHECK_CONTENT_LENGTH_HEADER"],
  name: "getCheckContentLengthHeaderPlugin",
  override: true
};
var getCheckContentLengthHeaderPlugin = (unused) => ({
  applyToStack: (clientStack) => {
    clientStack.add(checkContentLengthHeader(), checkContentLengthHeaderMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/region-redirect-endpoint-middleware.js
var regionRedirectEndpointMiddleware = (config) => {
  return (next, context) => async (args) => {
    const originalRegion = await config.region();
    const regionProviderRef = config.region;
    let unlock = () => {
    };
    if (context.__s3RegionRedirect) {
      Object.defineProperty(config, "region", {
        writable: false,
        value: async () => {
          return context.__s3RegionRedirect;
        }
      });
      unlock = () => Object.defineProperty(config, "region", {
        writable: true,
        value: regionProviderRef
      });
    }
    try {
      const result = await next(args);
      if (context.__s3RegionRedirect) {
        unlock();
        const region = await config.region();
        if (originalRegion !== region) {
          throw new Error("Region was not restored following S3 region redirect.");
        }
      }
      return result;
    } catch (e2) {
      unlock();
      throw e2;
    }
  };
};
var regionRedirectEndpointMiddlewareOptions = {
  tags: ["REGION_REDIRECT", "S3"],
  name: "regionRedirectEndpointMiddleware",
  override: true,
  relation: "before",
  toMiddleware: "endpointV2Middleware"
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/region-redirect-middleware.js
function regionRedirectMiddleware(clientConfig) {
  return (next, context) => async (args) => {
    try {
      return await next(args);
    } catch (err) {
      if (clientConfig.followRegionRedirects) {
        const statusCode = err?.$metadata?.httpStatusCode;
        const isHeadBucket = context.commandName === "HeadBucketCommand";
        const bucketRegionHeader = err?.$response?.headers?.["x-amz-bucket-region"];
        if (bucketRegionHeader) {
          if (statusCode === 301 || statusCode === 400 && (err?.name === "IllegalLocationConstraintException" || isHeadBucket)) {
            try {
              const actualRegion = bucketRegionHeader;
              context.logger?.debug(`Redirecting from ${await clientConfig.region()} to ${actualRegion}`);
              context.__s3RegionRedirect = actualRegion;
            } catch (e2) {
              throw new Error("Region redirect failed: " + e2);
            }
            return next(args);
          }
        }
      }
      throw err;
    }
  };
}
var regionRedirectMiddlewareOptions = {
  step: "initialize",
  tags: ["REGION_REDIRECT", "S3"],
  name: "regionRedirectMiddleware",
  override: true
};
var getRegionRedirectMiddlewarePlugin = (clientConfig) => ({
  applyToStack: (clientStack) => {
    clientStack.add(regionRedirectMiddleware(clientConfig), regionRedirectMiddlewareOptions);
    clientStack.addRelativeTo(regionRedirectEndpointMiddleware(clientConfig), regionRedirectEndpointMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/classes/S3ExpressIdentityCache.js
var S3ExpressIdentityCache = class _S3ExpressIdentityCache {
  data;
  lastPurgeTime = Date.now();
  static EXPIRED_CREDENTIAL_PURGE_INTERVAL_MS = 3e4;
  constructor(data = {}) {
    this.data = data;
  }
  get(key) {
    const entry = this.data[key];
    if (!entry) {
      return;
    }
    return entry;
  }
  set(key, entry) {
    this.data[key] = entry;
    return entry;
  }
  delete(key) {
    delete this.data[key];
  }
  async purgeExpired() {
    const now = Date.now();
    if (this.lastPurgeTime + _S3ExpressIdentityCache.EXPIRED_CREDENTIAL_PURGE_INTERVAL_MS > now) {
      return;
    }
    for (const key in this.data) {
      const entry = this.data[key];
      if (!entry.isRefreshing) {
        const credential = await entry.identity;
        if (credential.expiration) {
          if (credential.expiration.getTime() < now) {
            delete this.data[key];
          }
        }
      }
    }
  }
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/classes/S3ExpressIdentityCacheEntry.js
var S3ExpressIdentityCacheEntry = class {
  _identity;
  isRefreshing;
  accessed;
  constructor(_identity, isRefreshing = false, accessed = Date.now()) {
    this._identity = _identity;
    this.isRefreshing = isRefreshing;
    this.accessed = accessed;
  }
  get identity() {
    this.accessed = Date.now();
    return this._identity;
  }
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/classes/S3ExpressIdentityProviderImpl.js
var S3ExpressIdentityProviderImpl = class _S3ExpressIdentityProviderImpl {
  createSessionFn;
  cache;
  static REFRESH_WINDOW_MS = 6e4;
  constructor(createSessionFn, cache2 = new S3ExpressIdentityCache()) {
    this.createSessionFn = createSessionFn;
    this.cache = cache2;
  }
  async getS3ExpressIdentity(awsIdentity, identityProperties) {
    const key = identityProperties.Bucket;
    const { cache: cache2 } = this;
    const entry = cache2.get(key);
    if (entry) {
      return entry.identity.then((identity) => {
        const isExpired = (identity.expiration?.getTime() ?? 0) < Date.now();
        if (isExpired) {
          return cache2.set(key, new S3ExpressIdentityCacheEntry(this.getIdentity(key))).identity;
        }
        const isExpiringSoon = (identity.expiration?.getTime() ?? 0) < Date.now() + _S3ExpressIdentityProviderImpl.REFRESH_WINDOW_MS;
        if (isExpiringSoon && !entry.isRefreshing) {
          entry.isRefreshing = true;
          this.getIdentity(key).then((id) => {
            cache2.set(key, new S3ExpressIdentityCacheEntry(Promise.resolve(id)));
          });
        }
        return identity;
      });
    }
    return cache2.set(key, new S3ExpressIdentityCacheEntry(this.getIdentity(key))).identity;
  }
  async getIdentity(key) {
    await this.cache.purgeExpired().catch((error) => {
      console.warn("Error while clearing expired entries in S3ExpressIdentityCache: \n" + error);
    });
    const session = await this.createSessionFn(key);
    if (!session.Credentials?.AccessKeyId || !session.Credentials?.SecretAccessKey) {
      throw new Error("s3#createSession response credential missing AccessKeyId or SecretAccessKey.");
    }
    const identity = {
      accessKeyId: session.Credentials.AccessKeyId,
      secretAccessKey: session.Credentials.SecretAccessKey,
      sessionToken: session.Credentials.SessionToken,
      expiration: session.Credentials.Expiration ? new Date(session.Credentials.Expiration) : void 0
    };
    return identity;
  }
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/constants.js
var S3_EXPRESS_BUCKET_TYPE = "Directory";
var S3_EXPRESS_BACKEND = "S3Express";
var S3_EXPRESS_AUTH_SCHEME = "sigv4-s3express";
var SESSION_TOKEN_QUERY_PARAM = "X-Amz-S3session-Token";
var SESSION_TOKEN_HEADER = SESSION_TOKEN_QUERY_PARAM.toLowerCase();

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/classes/SignatureV4S3Express.js
var SignatureV4S3Express = class extends SignatureV4 {
  async signWithCredentials(requestToSign, credentials, options) {
    const credentialsWithoutSessionToken = getCredentialsWithoutSessionToken(credentials);
    requestToSign.headers[SESSION_TOKEN_HEADER] = credentials.sessionToken;
    const privateAccess = this;
    setSingleOverride(privateAccess, credentialsWithoutSessionToken);
    return privateAccess.signRequest(requestToSign, options ?? {});
  }
  async presignWithCredentials(requestToSign, credentials, options) {
    const credentialsWithoutSessionToken = getCredentialsWithoutSessionToken(credentials);
    delete requestToSign.headers[SESSION_TOKEN_HEADER];
    requestToSign.headers[SESSION_TOKEN_QUERY_PARAM] = credentials.sessionToken;
    requestToSign.query = requestToSign.query ?? {};
    requestToSign.query[SESSION_TOKEN_QUERY_PARAM] = credentials.sessionToken;
    const privateAccess = this;
    setSingleOverride(privateAccess, credentialsWithoutSessionToken);
    return this.presign(requestToSign, options);
  }
};
function getCredentialsWithoutSessionToken(credentials) {
  const credentialsWithoutSessionToken = {
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
    expiration: credentials.expiration
  };
  return credentialsWithoutSessionToken;
}
function setSingleOverride(privateAccess, credentialsWithoutSessionToken) {
  const id = setTimeout(() => {
    throw new Error("SignatureV4S3Express credential override was created but not called.");
  }, 10);
  const currentCredentialProvider = privateAccess.credentialProvider;
  const overrideCredentialsProviderOnce = () => {
    clearTimeout(id);
    privateAccess.credentialProvider = currentCredentialProvider;
    return Promise.resolve(credentialsWithoutSessionToken);
  };
  privateAccess.credentialProvider = overrideCredentialsProviderOnce;
}

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/functions/s3ExpressMiddleware.js
var s3ExpressMiddleware = (options) => {
  return (next, context) => async (args) => {
    if (context.endpointV2) {
      const endpoint = context.endpointV2;
      const isS3ExpressAuth = endpoint.properties?.authSchemes?.[0]?.name === S3_EXPRESS_AUTH_SCHEME;
      const isS3ExpressBucket = endpoint.properties?.backend === S3_EXPRESS_BACKEND || endpoint.properties?.bucketType === S3_EXPRESS_BUCKET_TYPE;
      if (isS3ExpressBucket) {
        setFeature(context, "S3_EXPRESS_BUCKET", "J");
        context.isS3ExpressBucket = true;
      }
      if (isS3ExpressAuth) {
        const requestBucket = args.input.Bucket;
        if (requestBucket) {
          const s3ExpressIdentity = await options.s3ExpressIdentityProvider.getS3ExpressIdentity(await options.credentials(), {
            Bucket: requestBucket
          });
          context.s3ExpressIdentity = s3ExpressIdentity;
          if (HttpRequest.isInstance(args.request) && s3ExpressIdentity.sessionToken) {
            args.request.headers[SESSION_TOKEN_HEADER] = s3ExpressIdentity.sessionToken;
          }
        }
      }
    }
    return next(args);
  };
};
var s3ExpressMiddlewareOptions = {
  name: "s3ExpressMiddleware",
  step: "build",
  tags: ["S3", "S3_EXPRESS"],
  override: true
};
var getS3ExpressPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(s3ExpressMiddleware(options), s3ExpressMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/functions/signS3Express.js
var signS3Express = async (s3ExpressIdentity, signingOptions, request, sigV4MultiRegionSigner) => {
  const signedRequest = await sigV4MultiRegionSigner.signWithCredentials(request, s3ExpressIdentity, {});
  if (signedRequest.headers["X-Amz-Security-Token"] || signedRequest.headers["x-amz-security-token"]) {
    throw new Error("X-Amz-Security-Token must not be set for s3-express requests.");
  }
  return signedRequest;
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3-express/functions/s3ExpressHttpSigningMiddleware.js
var defaultErrorHandler2 = (signingProperties) => (error) => {
  throw error;
};
var defaultSuccessHandler2 = (httpResponse, signingProperties) => {
};
var s3ExpressHttpSigningMiddleware = (config) => (next, context) => async (args) => {
  if (!HttpRequest.isInstance(args.request)) {
    return next(args);
  }
  const smithyContext = getSmithyContext(context);
  const scheme = smithyContext.selectedHttpAuthScheme;
  if (!scheme) {
    throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
  }
  const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
  let request;
  if (context.s3ExpressIdentity) {
    request = await signS3Express(context.s3ExpressIdentity, signingProperties, args.request, await config.signer());
  } else {
    request = await signer.sign(args.request, identity, signingProperties);
  }
  const output = await next({
    ...args,
    request
  }).catch((signer.errorHandler || defaultErrorHandler2)(signingProperties));
  (signer.successHandler || defaultSuccessHandler2)(output.response, signingProperties);
  return output;
};
var getS3ExpressHttpSigningPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(s3ExpressHttpSigningMiddleware(config), httpSigningMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/s3Configuration.js
var resolveS3Config = (input, { session }) => {
  const [s3ClientProvider, CreateSessionCommandCtor] = session;
  const { forcePathStyle, useAccelerateEndpoint, disableMultiregionAccessPoints, followRegionRedirects, s3ExpressIdentityProvider, bucketEndpoint, expectContinueHeader } = input;
  return Object.assign(input, {
    forcePathStyle: forcePathStyle ?? false,
    useAccelerateEndpoint: useAccelerateEndpoint ?? false,
    disableMultiregionAccessPoints: disableMultiregionAccessPoints ?? false,
    followRegionRedirects: followRegionRedirects ?? false,
    s3ExpressIdentityProvider: s3ExpressIdentityProvider ?? new S3ExpressIdentityProviderImpl(async (key) => s3ClientProvider().send(new CreateSessionCommandCtor({
      Bucket: key
    }))),
    bucketEndpoint: bucketEndpoint ?? false,
    expectContinueHeader: expectContinueHeader ?? 2097152
  });
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/throw-200-exceptions.js
var THROW_IF_EMPTY_BODY = {
  CopyObjectCommand: true,
  UploadPartCopyCommand: true,
  CompleteMultipartUploadCommand: true
};
var MAX_BYTES_TO_INSPECT = 3e3;
var throw200ExceptionsMiddleware = (config) => (next, context) => async (args) => {
  const result = await next(args);
  const { response } = result;
  if (!HttpResponse.isInstance(response)) {
    return result;
  }
  const { statusCode, body: sourceBody } = response;
  if (statusCode < 200 || statusCode >= 300) {
    return result;
  }
  const isSplittableStream = typeof sourceBody?.stream === "function" || typeof sourceBody?.pipe === "function" || typeof sourceBody?.tee === "function";
  if (!isSplittableStream) {
    return result;
  }
  let bodyCopy = sourceBody;
  let body = sourceBody;
  if (sourceBody && typeof sourceBody === "object" && !(sourceBody instanceof Uint8Array)) {
    [bodyCopy, body] = await splitStream(sourceBody);
  }
  response.body = body;
  const bodyBytes = await collectBody2(bodyCopy, {
    streamCollector: async (stream) => {
      return headStream(stream, MAX_BYTES_TO_INSPECT);
    }
  });
  if (typeof bodyCopy?.destroy === "function") {
    bodyCopy.destroy();
  }
  const bodyStringTail = config.utf8Encoder(bodyBytes.subarray(bodyBytes.length - 16));
  if (bodyBytes.length === 0 && THROW_IF_EMPTY_BODY[context.commandName]) {
    const err = new Error("S3 aborted request");
    err.name = "InternalError";
    throw err;
  }
  if (bodyStringTail && bodyStringTail.endsWith("</Error>")) {
    response.statusCode = 400;
  }
  return result;
};
var collectBody2 = (streamBody = new Uint8Array(), context) => {
  if (streamBody instanceof Uint8Array) {
    return Promise.resolve(streamBody);
  }
  return context.streamCollector(streamBody) || Promise.resolve(new Uint8Array());
};
var throw200ExceptionsMiddlewareOptions = {
  relation: "after",
  toMiddleware: "deserializerMiddleware",
  tags: ["THROW_200_EXCEPTIONS", "S3"],
  name: "throw200ExceptionsMiddleware",
  override: true
};
var getThrow200ExceptionsPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(throw200ExceptionsMiddleware(config), throw200ExceptionsMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/util-arn-parser/dist-es/index.js
var validate = (str) => typeof str === "string" && str.indexOf("arn:") === 0 && str.split(":").length >= 6;

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/bucket-endpoint-middleware.js
function bucketEndpointMiddleware(options) {
  return (next, context) => async (args) => {
    if (options.bucketEndpoint) {
      const endpoint = context.endpointV2;
      if (endpoint) {
        const bucket = args.input.Bucket;
        if (typeof bucket === "string") {
          try {
            const bucketEndpointUrl = new URL(bucket);
            context.endpointV2 = {
              ...endpoint,
              url: bucketEndpointUrl
            };
          } catch (e2) {
            const warning = `@aws-sdk/middleware-sdk-s3: bucketEndpoint=true was set but Bucket=${bucket} could not be parsed as URL.`;
            if (context.logger?.constructor?.name === "NoOpLogger") {
              console.warn(warning);
            } else {
              context.logger?.warn?.(warning);
            }
            throw e2;
          }
        }
      }
    }
    return next(args);
  };
}
var bucketEndpointMiddlewareOptions = {
  name: "bucketEndpointMiddleware",
  override: true,
  relation: "after",
  toMiddleware: "endpointV2Middleware"
};

// node_modules/@aws-sdk/middleware-sdk-s3/dist-es/validate-bucket-name.js
function validateBucketNameMiddleware({ bucketEndpoint }) {
  return (next) => async (args) => {
    const { input: { Bucket } } = args;
    if (!bucketEndpoint && typeof Bucket === "string" && !validate(Bucket) && Bucket.indexOf("/") >= 0) {
      const err = new Error(`Bucket name shouldn't contain '/', received '${Bucket}'`);
      err.name = "InvalidBucketName";
      throw err;
    }
    return next({ ...args });
  };
}
var validateBucketNameMiddlewareOptions = {
  step: "initialize",
  tags: ["VALIDATE_BUCKET_NAME"],
  name: "validateBucketNameMiddleware",
  override: true
};
var getValidateBucketNamePlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(validateBucketNameMiddleware(options), validateBucketNameMiddlewareOptions);
    clientStack.addRelativeTo(bucketEndpointMiddleware(options), bucketEndpointMiddlewareOptions);
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/configurations.js
var DEFAULT_UA_APP_ID = void 0;
function isValidUserAgentAppId(appId) {
  if (appId === void 0) {
    return true;
  }
  return typeof appId === "string" && appId.length <= 50;
}
function resolveUserAgentConfig(input) {
  const normalizedAppIdProvider = normalizeProvider2(input.userAgentAppId ?? DEFAULT_UA_APP_ID);
  const { customUserAgent } = input;
  return Object.assign(input, {
    customUserAgent: typeof customUserAgent === "string" ? [[customUserAgent]] : customUserAgent,
    userAgentAppId: async () => {
      const appId = await normalizedAppIdProvider();
      if (!isValidUserAgentAppId(appId)) {
        const logger2 = input.logger?.constructor?.name === "NoOpLogger" || !input.logger ? console : input.logger;
        if (typeof appId !== "string") {
          logger2?.warn("userAgentAppId must be a string or undefined.");
        } else if (appId.length > 50) {
          logger2?.warn("The provided userAgentAppId exceeds the maximum length of 50 characters.");
        }
      }
      return appId;
    }
  });
}

// node_modules/@smithy/util-endpoints/dist-es/cache/EndpointCache.js
var EndpointCache = class {
  capacity;
  data = /* @__PURE__ */ new Map();
  parameters = [];
  constructor({ size, params }) {
    this.capacity = size ?? 50;
    if (params) {
      this.parameters = params;
    }
  }
  get(endpointParams, resolver) {
    const key = this.hash(endpointParams);
    if (key === false) {
      return resolver();
    }
    if (!this.data.has(key)) {
      if (this.data.size > this.capacity + 10) {
        const keys = this.data.keys();
        let i2 = 0;
        while (true) {
          const { value, done } = keys.next();
          this.data.delete(value);
          if (done || ++i2 > 10) {
            break;
          }
        }
      }
      this.data.set(key, resolver());
    }
    return this.data.get(key);
  }
  size() {
    return this.data.size;
  }
  hash(endpointParams) {
    let buffer = "";
    const { parameters } = this;
    if (parameters.length === 0) {
      return false;
    }
    for (const param of parameters) {
      const val = String(endpointParams[param] ?? "");
      if (val.includes("|;")) {
        return false;
      }
      buffer += val + "|;";
    }
    return buffer;
  }
};

// node_modules/@smithy/util-endpoints/dist-es/lib/isIpAddress.js
var IP_V4_REGEX = new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
var isIpAddress = (value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]");

// node_modules/@smithy/util-endpoints/dist-es/lib/isValidHostLabel.js
var VALID_HOST_LABEL_REGEX = new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
var isValidHostLabel = (value, allowSubDomains = false) => {
  if (!allowSubDomains) {
    return VALID_HOST_LABEL_REGEX.test(value);
  }
  const labels = value.split(".");
  for (const label of labels) {
    if (!isValidHostLabel(label)) {
      return false;
    }
  }
  return true;
};

// node_modules/@smithy/util-endpoints/dist-es/utils/customEndpointFunctions.js
var customEndpointFunctions = {};

// node_modules/@smithy/util-endpoints/dist-es/debug/debugId.js
var debugId = "endpoints";

// node_modules/@smithy/util-endpoints/dist-es/debug/toDebugString.js
function toDebugString(input) {
  if (typeof input !== "object" || input == null) {
    return input;
  }
  if ("ref" in input) {
    return `$${toDebugString(input.ref)}`;
  }
  if ("fn" in input) {
    return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
  }
  return JSON.stringify(input, null, 2);
}

// node_modules/@smithy/util-endpoints/dist-es/types/EndpointError.js
var EndpointError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "EndpointError";
  }
};

// node_modules/@smithy/util-endpoints/dist-es/lib/booleanEquals.js
var booleanEquals = (value1, value2) => value1 === value2;

// node_modules/@smithy/util-endpoints/dist-es/lib/getAttrPathList.js
var getAttrPathList = (path) => {
  const parts = path.split(".");
  const pathList = [];
  for (const part of parts) {
    const squareBracketIndex = part.indexOf("[");
    if (squareBracketIndex !== -1) {
      if (part.indexOf("]") !== part.length - 1) {
        throw new EndpointError(`Path: '${path}' does not end with ']'`);
      }
      const arrayIndex = part.slice(squareBracketIndex + 1, -1);
      if (Number.isNaN(parseInt(arrayIndex))) {
        throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
      }
      if (squareBracketIndex !== 0) {
        pathList.push(part.slice(0, squareBracketIndex));
      }
      pathList.push(arrayIndex);
    } else {
      pathList.push(part);
    }
  }
  return pathList;
};

// node_modules/@smithy/util-endpoints/dist-es/lib/getAttr.js
var getAttr = (value, path) => getAttrPathList(path).reduce((acc, index) => {
  if (typeof acc !== "object") {
    throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
  } else if (Array.isArray(acc)) {
    return acc[parseInt(index)];
  }
  return acc[index];
}, value);

// node_modules/@smithy/util-endpoints/dist-es/lib/isSet.js
var isSet = (value) => value != null;

// node_modules/@smithy/util-endpoints/dist-es/lib/not.js
var not = (value) => !value;

// node_modules/@smithy/util-endpoints/dist-es/lib/parseURL.js
var DEFAULT_PORTS = {
  [EndpointURLScheme.HTTP]: 80,
  [EndpointURLScheme.HTTPS]: 443
};
var parseURL = (value) => {
  const whatwgURL = (() => {
    try {
      if (value instanceof URL) {
        return value;
      }
      if (typeof value === "object" && "hostname" in value) {
        const { hostname: hostname2, port, protocol: protocol2 = "", path = "", query = {} } = value;
        const url = new URL(`${protocol2}//${hostname2}${port ? `:${port}` : ""}${path}`);
        url.search = Object.entries(query).map(([k2, v2]) => `${k2}=${v2}`).join("&");
        return url;
      }
      return new URL(value);
    } catch (error) {
      return null;
    }
  })();
  if (!whatwgURL) {
    console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
    return null;
  }
  const urlString = whatwgURL.href;
  const { host, hostname, pathname, protocol, search } = whatwgURL;
  if (search) {
    return null;
  }
  const scheme = protocol.slice(0, -1);
  if (!Object.values(EndpointURLScheme).includes(scheme)) {
    return null;
  }
  const isIp = isIpAddress(hostname);
  const inputContainsDefaultPort = urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`);
  const authority = `${host}${inputContainsDefaultPort ? `:${DEFAULT_PORTS[scheme]}` : ``}`;
  return {
    scheme,
    authority,
    path: pathname,
    normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
    isIp
  };
};

// node_modules/@smithy/util-endpoints/dist-es/lib/stringEquals.js
var stringEquals = (value1, value2) => value1 === value2;

// node_modules/@smithy/util-endpoints/dist-es/lib/substring.js
var substring = (input, start, stop, reverse) => {
  if (start >= stop || input.length < stop) {
    return null;
  }
  if (!reverse) {
    return input.substring(start, stop);
  }
  return input.substring(input.length - stop, input.length - start);
};

// node_modules/@smithy/util-endpoints/dist-es/lib/uriEncode.js
var uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c2) => `%${c2.charCodeAt(0).toString(16).toUpperCase()}`);

// node_modules/@smithy/util-endpoints/dist-es/utils/endpointFunctions.js
var endpointFunctions = {
  booleanEquals,
  getAttr,
  isSet,
  isValidHostLabel,
  not,
  parseURL,
  stringEquals,
  substring,
  uriEncode
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateTemplate.js
var evaluateTemplate = (template, options) => {
  const evaluatedTemplateArr = [];
  const templateContext = {
    ...options.endpointParams,
    ...options.referenceRecord
  };
  let currentIndex = 0;
  while (currentIndex < template.length) {
    const openingBraceIndex = template.indexOf("{", currentIndex);
    if (openingBraceIndex === -1) {
      evaluatedTemplateArr.push(template.slice(currentIndex));
      break;
    }
    evaluatedTemplateArr.push(template.slice(currentIndex, openingBraceIndex));
    const closingBraceIndex = template.indexOf("}", openingBraceIndex);
    if (closingBraceIndex === -1) {
      evaluatedTemplateArr.push(template.slice(openingBraceIndex));
      break;
    }
    if (template[openingBraceIndex + 1] === "{" && template[closingBraceIndex + 1] === "}") {
      evaluatedTemplateArr.push(template.slice(openingBraceIndex + 1, closingBraceIndex));
      currentIndex = closingBraceIndex + 2;
    }
    const parameterName = template.substring(openingBraceIndex + 1, closingBraceIndex);
    if (parameterName.includes("#")) {
      const [refName, attrName] = parameterName.split("#");
      evaluatedTemplateArr.push(getAttr(templateContext[refName], attrName));
    } else {
      evaluatedTemplateArr.push(templateContext[parameterName]);
    }
    currentIndex = closingBraceIndex + 1;
  }
  return evaluatedTemplateArr.join("");
};

// node_modules/@smithy/util-endpoints/dist-es/utils/getReferenceValue.js
var getReferenceValue = ({ ref }, options) => {
  const referenceRecord = {
    ...options.endpointParams,
    ...options.referenceRecord
  };
  return referenceRecord[ref];
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateExpression.js
var evaluateExpression = (obj, keyName, options) => {
  if (typeof obj === "string") {
    return evaluateTemplate(obj, options);
  } else if (obj["fn"]) {
    return group.callFunction(obj, options);
  } else if (obj["ref"]) {
    return getReferenceValue(obj, options);
  }
  throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
};
var callFunction = ({ fn, argv }, options) => {
  const evaluatedArgs = argv.map((arg) => ["boolean", "number"].includes(typeof arg) ? arg : group.evaluateExpression(arg, "arg", options));
  const fnSegments = fn.split(".");
  if (fnSegments[0] in customEndpointFunctions && fnSegments[1] != null) {
    return customEndpointFunctions[fnSegments[0]][fnSegments[1]](...evaluatedArgs);
  }
  return endpointFunctions[fn](...evaluatedArgs);
};
var group = {
  evaluateExpression,
  callFunction
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateCondition.js
var evaluateCondition = ({ assign, ...fnArgs }, options) => {
  if (assign && assign in options.referenceRecord) {
    throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
  }
  const value = callFunction(fnArgs, options);
  options.logger?.debug?.(`${debugId} evaluateCondition: ${toDebugString(fnArgs)} = ${toDebugString(value)}`);
  return {
    result: value === "" ? true : !!value,
    ...assign != null && { toAssign: { name: assign, value } }
  };
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateConditions.js
var evaluateConditions = (conditions = [], options) => {
  const conditionsReferenceRecord = {};
  for (const condition of conditions) {
    const { result, toAssign } = evaluateCondition(condition, {
      ...options,
      referenceRecord: {
        ...options.referenceRecord,
        ...conditionsReferenceRecord
      }
    });
    if (!result) {
      return { result };
    }
    if (toAssign) {
      conditionsReferenceRecord[toAssign.name] = toAssign.value;
      options.logger?.debug?.(`${debugId} assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
    }
  }
  return { result: true, referenceRecord: conditionsReferenceRecord };
};

// node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointHeaders.js
var getEndpointHeaders = (headers, options) => Object.entries(headers).reduce((acc, [headerKey, headerVal]) => ({
  ...acc,
  [headerKey]: headerVal.map((headerValEntry) => {
    const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
    if (typeof processedExpr !== "string") {
      throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
    }
    return processedExpr;
  })
}), {});

// node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointProperties.js
var getEndpointProperties = (properties, options) => Object.entries(properties).reduce((acc, [propertyKey, propertyVal]) => ({
  ...acc,
  [propertyKey]: group2.getEndpointProperty(propertyVal, options)
}), {});
var getEndpointProperty = (property, options) => {
  if (Array.isArray(property)) {
    return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
  }
  switch (typeof property) {
    case "string":
      return evaluateTemplate(property, options);
    case "object":
      if (property === null) {
        throw new EndpointError(`Unexpected endpoint property: ${property}`);
      }
      return group2.getEndpointProperties(property, options);
    case "boolean":
      return property;
    default:
      throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
  }
};
var group2 = {
  getEndpointProperty,
  getEndpointProperties
};

// node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointUrl.js
var getEndpointUrl = (endpointUrl, options) => {
  const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
  if (typeof expression === "string") {
    try {
      return new URL(expression);
    } catch (error) {
      console.error(`Failed to construct URL with ${expression}`, error);
      throw error;
    }
  }
  throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateEndpointRule.js
var evaluateEndpointRule = (endpointRule, options) => {
  const { conditions, endpoint } = endpointRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  const endpointRuleOptions = {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  };
  const { url, properties, headers } = endpoint;
  options.logger?.debug?.(`${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
  return {
    ...headers != void 0 && {
      headers: getEndpointHeaders(headers, endpointRuleOptions)
    },
    ...properties != void 0 && {
      properties: getEndpointProperties(properties, endpointRuleOptions)
    },
    url: getEndpointUrl(url, endpointRuleOptions)
  };
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateErrorRule.js
var evaluateErrorRule = (errorRule, options) => {
  const { conditions, error } = errorRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  throw new EndpointError(evaluateExpression(error, "Error", {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  }));
};

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateRules.js
var evaluateRules = (rules, options) => {
  for (const rule of rules) {
    if (rule.type === "endpoint") {
      const endpointOrUndefined = evaluateEndpointRule(rule, options);
      if (endpointOrUndefined) {
        return endpointOrUndefined;
      }
    } else if (rule.type === "error") {
      evaluateErrorRule(rule, options);
    } else if (rule.type === "tree") {
      const endpointOrUndefined = group3.evaluateTreeRule(rule, options);
      if (endpointOrUndefined) {
        return endpointOrUndefined;
      }
    } else {
      throw new EndpointError(`Unknown endpoint rule: ${rule}`);
    }
  }
  throw new EndpointError(`Rules evaluation failed`);
};
var evaluateTreeRule = (treeRule, options) => {
  const { conditions, rules } = treeRule;
  const { result, referenceRecord } = evaluateConditions(conditions, options);
  if (!result) {
    return;
  }
  return group3.evaluateRules(rules, {
    ...options,
    referenceRecord: { ...options.referenceRecord, ...referenceRecord }
  });
};
var group3 = {
  evaluateRules,
  evaluateTreeRule
};

// node_modules/@smithy/util-endpoints/dist-es/resolveEndpoint.js
var resolveEndpoint = (ruleSetObject, options) => {
  const { endpointParams, logger: logger2 } = options;
  const { parameters, rules } = ruleSetObject;
  options.logger?.debug?.(`${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
  const paramsWithDefault = Object.entries(parameters).filter(([, v2]) => v2.default != null).map(([k2, v2]) => [k2, v2.default]);
  if (paramsWithDefault.length > 0) {
    for (const [paramKey, paramDefaultValue] of paramsWithDefault) {
      endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
    }
  }
  const requiredParams = Object.entries(parameters).filter(([, v2]) => v2.required).map(([k2]) => k2);
  for (const requiredParam of requiredParams) {
    if (endpointParams[requiredParam] == null) {
      throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
    }
  }
  const endpoint = evaluateRules(rules, { endpointParams, logger: logger2, referenceRecord: {} });
  options.logger?.debug?.(`${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
  return endpoint;
};

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/isVirtualHostableS3Bucket.js
var isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
  if (allowSubDomains) {
    for (const label of value.split(".")) {
      if (!isVirtualHostableS3Bucket(label)) {
        return false;
      }
    }
    return true;
  }
  if (!isValidHostLabel(value)) {
    return false;
  }
  if (value.length < 3 || value.length > 63) {
    return false;
  }
  if (value !== value.toLowerCase()) {
    return false;
  }
  if (isIpAddress(value)) {
    return false;
  }
  return true;
};

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/parseArn.js
var ARN_DELIMITER = ":";
var RESOURCE_DELIMITER = "/";
var parseArn = (value) => {
  const segments = value.split(ARN_DELIMITER);
  if (segments.length < 6)
    return null;
  const [arn, partition2, service, region, accountId, ...resourcePath] = segments;
  if (arn !== "arn" || partition2 === "" || service === "" || resourcePath.join(ARN_DELIMITER) === "")
    return null;
  const resourceId = resourcePath.map((resource) => resource.split(RESOURCE_DELIMITER)).flat();
  return {
    partition: partition2,
    service,
    region,
    accountId,
    resourceId
  };
};

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partitions.json
var partitions_default = {
  partitions: [{
    id: "aws",
    outputs: {
      dnsSuffix: "amazonaws.com",
      dualStackDnsSuffix: "api.aws",
      implicitGlobalRegion: "us-east-1",
      name: "aws",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^(us|eu|ap|sa|ca|me|af|il|mx)\\-\\w+\\-\\d+$",
    regions: {
      "af-south-1": {
        description: "Africa (Cape Town)"
      },
      "ap-east-1": {
        description: "Asia Pacific (Hong Kong)"
      },
      "ap-east-2": {
        description: "Asia Pacific (Taipei)"
      },
      "ap-northeast-1": {
        description: "Asia Pacific (Tokyo)"
      },
      "ap-northeast-2": {
        description: "Asia Pacific (Seoul)"
      },
      "ap-northeast-3": {
        description: "Asia Pacific (Osaka)"
      },
      "ap-south-1": {
        description: "Asia Pacific (Mumbai)"
      },
      "ap-south-2": {
        description: "Asia Pacific (Hyderabad)"
      },
      "ap-southeast-1": {
        description: "Asia Pacific (Singapore)"
      },
      "ap-southeast-2": {
        description: "Asia Pacific (Sydney)"
      },
      "ap-southeast-3": {
        description: "Asia Pacific (Jakarta)"
      },
      "ap-southeast-4": {
        description: "Asia Pacific (Melbourne)"
      },
      "ap-southeast-5": {
        description: "Asia Pacific (Malaysia)"
      },
      "ap-southeast-6": {
        description: "Asia Pacific (New Zealand)"
      },
      "ap-southeast-7": {
        description: "Asia Pacific (Thailand)"
      },
      "aws-global": {
        description: "aws global region"
      },
      "ca-central-1": {
        description: "Canada (Central)"
      },
      "ca-west-1": {
        description: "Canada West (Calgary)"
      },
      "eu-central-1": {
        description: "Europe (Frankfurt)"
      },
      "eu-central-2": {
        description: "Europe (Zurich)"
      },
      "eu-north-1": {
        description: "Europe (Stockholm)"
      },
      "eu-south-1": {
        description: "Europe (Milan)"
      },
      "eu-south-2": {
        description: "Europe (Spain)"
      },
      "eu-west-1": {
        description: "Europe (Ireland)"
      },
      "eu-west-2": {
        description: "Europe (London)"
      },
      "eu-west-3": {
        description: "Europe (Paris)"
      },
      "il-central-1": {
        description: "Israel (Tel Aviv)"
      },
      "me-central-1": {
        description: "Middle East (UAE)"
      },
      "me-south-1": {
        description: "Middle East (Bahrain)"
      },
      "mx-central-1": {
        description: "Mexico (Central)"
      },
      "sa-east-1": {
        description: "South America (Sao Paulo)"
      },
      "us-east-1": {
        description: "US East (N. Virginia)"
      },
      "us-east-2": {
        description: "US East (Ohio)"
      },
      "us-west-1": {
        description: "US West (N. California)"
      },
      "us-west-2": {
        description: "US West (Oregon)"
      }
    }
  }, {
    id: "aws-cn",
    outputs: {
      dnsSuffix: "amazonaws.com.cn",
      dualStackDnsSuffix: "api.amazonwebservices.com.cn",
      implicitGlobalRegion: "cn-northwest-1",
      name: "aws-cn",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^cn\\-\\w+\\-\\d+$",
    regions: {
      "aws-cn-global": {
        description: "aws-cn global region"
      },
      "cn-north-1": {
        description: "China (Beijing)"
      },
      "cn-northwest-1": {
        description: "China (Ningxia)"
      }
    }
  }, {
    id: "aws-eusc",
    outputs: {
      dnsSuffix: "amazonaws.eu",
      dualStackDnsSuffix: "api.amazonwebservices.eu",
      implicitGlobalRegion: "eusc-de-east-1",
      name: "aws-eusc",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^eusc\\-(de)\\-\\w+\\-\\d+$",
    regions: {
      "eusc-de-east-1": {
        description: "EU (Germany)"
      }
    }
  }, {
    id: "aws-iso",
    outputs: {
      dnsSuffix: "c2s.ic.gov",
      dualStackDnsSuffix: "api.aws.ic.gov",
      implicitGlobalRegion: "us-iso-east-1",
      name: "aws-iso",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^us\\-iso\\-\\w+\\-\\d+$",
    regions: {
      "aws-iso-global": {
        description: "aws-iso global region"
      },
      "us-iso-east-1": {
        description: "US ISO East"
      },
      "us-iso-west-1": {
        description: "US ISO WEST"
      }
    }
  }, {
    id: "aws-iso-b",
    outputs: {
      dnsSuffix: "sc2s.sgov.gov",
      dualStackDnsSuffix: "api.aws.scloud",
      implicitGlobalRegion: "us-isob-east-1",
      name: "aws-iso-b",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^us\\-isob\\-\\w+\\-\\d+$",
    regions: {
      "aws-iso-b-global": {
        description: "aws-iso-b global region"
      },
      "us-isob-east-1": {
        description: "US ISOB East (Ohio)"
      },
      "us-isob-west-1": {
        description: "US ISOB West"
      }
    }
  }, {
    id: "aws-iso-e",
    outputs: {
      dnsSuffix: "cloud.adc-e.uk",
      dualStackDnsSuffix: "api.cloud-aws.adc-e.uk",
      implicitGlobalRegion: "eu-isoe-west-1",
      name: "aws-iso-e",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^eu\\-isoe\\-\\w+\\-\\d+$",
    regions: {
      "aws-iso-e-global": {
        description: "aws-iso-e global region"
      },
      "eu-isoe-west-1": {
        description: "EU ISOE West"
      }
    }
  }, {
    id: "aws-iso-f",
    outputs: {
      dnsSuffix: "csp.hci.ic.gov",
      dualStackDnsSuffix: "api.aws.hci.ic.gov",
      implicitGlobalRegion: "us-isof-south-1",
      name: "aws-iso-f",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^us\\-isof\\-\\w+\\-\\d+$",
    regions: {
      "aws-iso-f-global": {
        description: "aws-iso-f global region"
      },
      "us-isof-east-1": {
        description: "US ISOF EAST"
      },
      "us-isof-south-1": {
        description: "US ISOF SOUTH"
      }
    }
  }, {
    id: "aws-us-gov",
    outputs: {
      dnsSuffix: "amazonaws.com",
      dualStackDnsSuffix: "api.aws",
      implicitGlobalRegion: "us-gov-west-1",
      name: "aws-us-gov",
      supportsDualStack: true,
      supportsFIPS: true
    },
    regionRegex: "^us\\-gov\\-\\w+\\-\\d+$",
    regions: {
      "aws-us-gov-global": {
        description: "aws-us-gov global region"
      },
      "us-gov-east-1": {
        description: "AWS GovCloud (US-East)"
      },
      "us-gov-west-1": {
        description: "AWS GovCloud (US-West)"
      }
    }
  }],
  version: "1.1"
};

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partition.js
var selectedPartitionsInfo = partitions_default;
var selectedUserAgentPrefix = "";
var partition = (value) => {
  const { partitions } = selectedPartitionsInfo;
  for (const partition2 of partitions) {
    const { regions, outputs } = partition2;
    for (const [region, regionData] of Object.entries(regions)) {
      if (region === value) {
        return {
          ...outputs,
          ...regionData
        };
      }
    }
  }
  for (const partition2 of partitions) {
    const { regionRegex, outputs } = partition2;
    if (new RegExp(regionRegex).test(value)) {
      return {
        ...outputs
      };
    }
  }
  const DEFAULT_PARTITION = partitions.find((partition2) => partition2.id === "aws");
  if (!DEFAULT_PARTITION) {
    throw new Error("Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist.");
  }
  return {
    ...DEFAULT_PARTITION.outputs
  };
};
var getUserAgentPrefix = () => selectedUserAgentPrefix;

// node_modules/@aws-sdk/util-endpoints/dist-es/aws.js
var awsEndpointFunctions = {
  isVirtualHostableS3Bucket,
  parseArn,
  partition
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@smithy/querystring-parser/dist-es/index.js
function parseQueryString(querystring) {
  const query = {};
  querystring = querystring.replace(/^\?/, "");
  if (querystring) {
    for (const pair of querystring.split("&")) {
      let [key, value = null] = pair.split("=");
      key = decodeURIComponent(key);
      if (value) {
        value = decodeURIComponent(value);
      }
      if (!(key in query)) {
        query[key] = value;
      } else if (Array.isArray(query[key])) {
        query[key].push(value);
      } else {
        query[key] = [query[key], value];
      }
    }
  }
  return query;
}

// node_modules/@smithy/url-parser/dist-es/index.js
var parseUrl = (url) => {
  if (typeof url === "string") {
    return parseUrl(new URL(url));
  }
  const { hostname, pathname, port, protocol, search } = url;
  let query;
  if (search) {
    query = parseQueryString(search);
  }
  return {
    hostname,
    port: port ? parseInt(port) : void 0,
    protocol,
    path: pathname,
    query
  };
};

// node_modules/@aws-sdk/middleware-user-agent/dist-es/check-features.js
var ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
async function checkFeatures(context, config, args) {
  const request = args.request;
  if (request?.headers?.["smithy-protocol"] === "rpc-v2-cbor") {
    setFeature(context, "PROTOCOL_RPC_V2_CBOR", "M");
  }
  if (typeof config.retryStrategy === "function") {
    const retryStrategy = await config.retryStrategy();
    if (typeof retryStrategy.acquireInitialRetryToken === "function") {
      if (retryStrategy.constructor?.name?.includes("Adaptive")) {
        setFeature(context, "RETRY_MODE_ADAPTIVE", "F");
      } else {
        setFeature(context, "RETRY_MODE_STANDARD", "E");
      }
    } else {
      setFeature(context, "RETRY_MODE_LEGACY", "D");
    }
  }
  if (typeof config.accountIdEndpointMode === "function") {
    const endpointV2 = context.endpointV2;
    if (String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)) {
      setFeature(context, "ACCOUNT_ID_ENDPOINT", "O");
    }
    switch (await config.accountIdEndpointMode?.()) {
      case "disabled":
        setFeature(context, "ACCOUNT_ID_MODE_DISABLED", "Q");
        break;
      case "preferred":
        setFeature(context, "ACCOUNT_ID_MODE_PREFERRED", "P");
        break;
      case "required":
        setFeature(context, "ACCOUNT_ID_MODE_REQUIRED", "R");
        break;
    }
  }
  const identity = context.__smithy_context?.selectedHttpAuthScheme?.identity;
  if (identity?.$source) {
    const credentials = identity;
    if (credentials.accountId) {
      setFeature(context, "RESOLVED_ACCOUNT_ID", "T");
    }
    for (const [key, value] of Object.entries(credentials.$source ?? {})) {
      setFeature(context, key, value);
    }
  }
}

// node_modules/@aws-sdk/middleware-user-agent/dist-es/constants.js
var USER_AGENT = "user-agent";
var X_AMZ_USER_AGENT = "x-amz-user-agent";
var SPACE = " ";
var UA_NAME_SEPARATOR = "/";
var UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
var UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
var UA_ESCAPE_CHAR = "-";

// node_modules/@aws-sdk/middleware-user-agent/dist-es/encode-features.js
var BYTE_LIMIT = 1024;
function encodeFeatures(features) {
  let buffer = "";
  for (const key in features) {
    const val = features[key];
    if (buffer.length + val.length + 1 <= BYTE_LIMIT) {
      if (buffer.length) {
        buffer += "," + val;
      } else {
        buffer += val;
      }
      continue;
    }
    break;
  }
  return buffer;
}

// node_modules/@aws-sdk/middleware-user-agent/dist-es/user-agent-middleware.js
var userAgentMiddleware = (options) => (next, context) => async (args) => {
  const { request } = args;
  if (!HttpRequest.isInstance(request)) {
    return next(args);
  }
  const { headers } = request;
  const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
  const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
  await checkFeatures(context, options, args);
  const awsContext = context;
  defaultUserAgent.push(`m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`);
  const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
  const appId = await options.userAgentAppId();
  if (appId) {
    defaultUserAgent.push(escapeUserAgent([`app`, `${appId}`]));
  }
  const prefix = getUserAgentPrefix();
  const sdkUserAgentValue = (prefix ? [prefix] : []).concat([...defaultUserAgent, ...userAgent, ...customUserAgent]).join(SPACE);
  const normalUAValue = [
    ...defaultUserAgent.filter((section) => section.startsWith("aws-sdk-")),
    ...customUserAgent
  ].join(SPACE);
  if (options.runtime !== "browser") {
    if (normalUAValue) {
      headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT] ? `${headers[USER_AGENT]} ${normalUAValue}` : normalUAValue;
    }
    headers[USER_AGENT] = sdkUserAgentValue;
  } else {
    headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
  }
  return next({
    ...args,
    request
  });
};
var escapeUserAgent = (userAgentPair) => {
  const name = userAgentPair[0].split(UA_NAME_SEPARATOR).map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR)).join(UA_NAME_SEPARATOR);
  const version = userAgentPair[1]?.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
  const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
  const prefix = name.substring(0, prefixSeparatorIndex);
  let uaName = name.substring(prefixSeparatorIndex + 1);
  if (prefix === "api") {
    uaName = uaName.toLowerCase();
  }
  return [prefix, uaName, version].filter((item) => item && item.length > 0).reduce((acc, item, index) => {
    switch (index) {
      case 0:
        return item;
      case 1:
        return `${acc}/${item}`;
      default:
        return `${acc}#${item}`;
    }
  }, "");
};
var getUserAgentMiddlewareOptions = {
  name: "getUserAgentMiddleware",
  step: "build",
  priority: "low",
  tags: ["SET_USER_AGENT", "USER_AGENT"],
  override: true
};
var getUserAgentPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
  }
});

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseDualstackEndpointConfigOptions.js
var DEFAULT_USE_DUALSTACK_ENDPOINT = false;

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseFipsEndpointConfigOptions.js
var DEFAULT_USE_FIPS_ENDPOINT = false;

// node_modules/@smithy/config-resolver/dist-es/regionConfig/checkRegion.js
var validRegions = /* @__PURE__ */ new Set();
var checkRegion = (region, check = isValidHostLabel) => {
  if (!validRegions.has(region) && !check(region)) {
    if (region === "*") {
      console.warn(`@smithy/config-resolver WARN - Please use the caller region instead of "*". See "sigv4a" in https://github.com/aws/aws-sdk-js-v3/blob/main/supplemental-docs/CLIENTS.md.`);
    } else {
      throw new Error(`Region not accepted: region="${region}" is not a valid hostname component.`);
    }
  } else {
    validRegions.add(region);
  }
};

// node_modules/@smithy/config-resolver/dist-es/regionConfig/isFipsRegion.js
var isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));

// node_modules/@smithy/config-resolver/dist-es/regionConfig/getRealRegion.js
var getRealRegion = (region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region;

// node_modules/@smithy/config-resolver/dist-es/regionConfig/resolveRegionConfig.js
var resolveRegionConfig = (input) => {
  const { region, useFipsEndpoint } = input;
  if (!region) {
    throw new Error("Region is missing");
  }
  return Object.assign(input, {
    region: async () => {
      const providedRegion = typeof region === "function" ? await region() : region;
      const realRegion = getRealRegion(providedRegion);
      checkRegion(realRegion);
      return realRegion;
    },
    useFipsEndpoint: async () => {
      const providedRegion = typeof region === "string" ? region : await region();
      if (isFipsRegion(providedRegion)) {
        return true;
      }
      return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
    }
  });
};

// node_modules/@smithy/eventstream-serde-config-resolver/dist-es/EventStreamSerdeConfig.js
var resolveEventStreamSerdeConfig = (input) => Object.assign(input, {
  eventStreamMarshaller: input.eventStreamSerdeProvider(input)
});

// node_modules/@smithy/middleware-content-length/dist-es/index.js
var CONTENT_LENGTH_HEADER2 = "content-length";
function contentLengthMiddleware(bodyLengthChecker) {
  return (next) => async (args) => {
    const request = args.request;
    if (HttpRequest.isInstance(request)) {
      const { body, headers } = request;
      if (body && Object.keys(headers).map((str) => str.toLowerCase()).indexOf(CONTENT_LENGTH_HEADER2) === -1) {
        try {
          const length = bodyLengthChecker(body);
          request.headers = {
            ...request.headers,
            [CONTENT_LENGTH_HEADER2]: String(length)
          };
        } catch (error) {
        }
      }
    }
    return next({
      ...args,
      request
    });
  };
}
var contentLengthMiddlewareOptions = {
  step: "build",
  tags: ["SET_CONTENT_LENGTH", "CONTENT_LENGTH"],
  name: "contentLengthMiddleware",
  override: true
};
var getContentLengthPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(contentLengthMiddleware(options.bodyLengthChecker), contentLengthMiddlewareOptions);
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/service-customizations/s3.js
var resolveParamsForS3 = async (endpointParams) => {
  const bucket = endpointParams?.Bucket || "";
  if (typeof endpointParams.Bucket === "string") {
    endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
  }
  if (isArnBucketName(bucket)) {
    if (endpointParams.ForcePathStyle === true) {
      throw new Error("Path-style addressing cannot be used with ARN buckets");
    }
  } else if (!isDnsCompatibleBucketName(bucket) || bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:") || bucket.toLowerCase() !== bucket || bucket.length < 3) {
    endpointParams.ForcePathStyle = true;
  }
  if (endpointParams.DisableMultiRegionAccessPoints) {
    endpointParams.disableMultiRegionAccessPoints = true;
    endpointParams.DisableMRAP = true;
  }
  return endpointParams;
};
var DOMAIN_PATTERN = /^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$/;
var IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
var DOTS_PATTERN = /\.\./;
var isDnsCompatibleBucketName = (bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName);
var isArnBucketName = (bucketName) => {
  const [arn, partition2, service, , , bucket] = bucketName.split(":");
  const isArn = arn === "arn" && bucketName.split(":").length >= 6;
  const isValidArn = Boolean(isArn && partition2 && service && bucket);
  if (isArn && !isValidArn) {
    throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
  }
  return isValidArn;
};

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/createConfigValueProvider.js
var createConfigValueProvider = (configKey, canonicalEndpointParamKey, config) => {
  const configProvider = async () => {
    const configValue = config[configKey] ?? config[canonicalEndpointParamKey];
    if (typeof configValue === "function") {
      return configValue();
    }
    return configValue;
  };
  if (configKey === "credentialScope" || canonicalEndpointParamKey === "CredentialScope") {
    return async () => {
      const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
      const configValue = credentials?.credentialScope ?? credentials?.CredentialScope;
      return configValue;
    };
  }
  if (configKey === "accountId" || canonicalEndpointParamKey === "AccountId") {
    return async () => {
      const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
      const configValue = credentials?.accountId ?? credentials?.AccountId;
      return configValue;
    };
  }
  if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") {
    return async () => {
      if (config.isCustomEndpoint === false) {
        return void 0;
      }
      const endpoint = await configProvider();
      if (endpoint && typeof endpoint === "object") {
        if ("url" in endpoint) {
          return endpoint.url.href;
        }
        if ("hostname" in endpoint) {
          const { protocol, hostname, port, path } = endpoint;
          return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
        }
      }
      return endpoint;
    };
  }
  return configProvider;
};

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromConfig.browser.js
var getEndpointFromConfig = async (serviceId) => void 0;

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/toEndpointV1.js
var toEndpointV1 = (endpoint) => {
  if (typeof endpoint === "object") {
    if ("url" in endpoint) {
      return parseUrl(endpoint.url);
    }
    return endpoint;
  }
  return parseUrl(endpoint);
};

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromInstructions.js
var getEndpointFromInstructions = async (commandInput, instructionsSupplier, clientConfig, context) => {
  if (!clientConfig.isCustomEndpoint) {
    let endpointFromConfig;
    if (clientConfig.serviceConfiguredEndpoint) {
      endpointFromConfig = await clientConfig.serviceConfiguredEndpoint();
    } else {
      endpointFromConfig = await getEndpointFromConfig(clientConfig.serviceId);
    }
    if (endpointFromConfig) {
      clientConfig.endpoint = () => Promise.resolve(toEndpointV1(endpointFromConfig));
      clientConfig.isCustomEndpoint = true;
    }
  }
  const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
  if (typeof clientConfig.endpointProvider !== "function") {
    throw new Error("config.endpointProvider is not set.");
  }
  const endpoint = clientConfig.endpointProvider(endpointParams, context);
  return endpoint;
};
var resolveParams = async (commandInput, instructionsSupplier, clientConfig) => {
  const endpointParams = {};
  const instructions = instructionsSupplier?.getEndpointParameterInstructions?.() || {};
  for (const [name, instruction] of Object.entries(instructions)) {
    switch (instruction.type) {
      case "staticContextParams":
        endpointParams[name] = instruction.value;
        break;
      case "contextParams":
        endpointParams[name] = commandInput[instruction.name];
        break;
      case "clientContextParams":
      case "builtInParams":
        endpointParams[name] = await createConfigValueProvider(instruction.name, name, clientConfig)();
        break;
      case "operationContextParams":
        endpointParams[name] = instruction.get(commandInput);
        break;
      default:
        throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
    }
  }
  if (Object.keys(instructions).length === 0) {
    Object.assign(endpointParams, clientConfig);
  }
  if (String(clientConfig.serviceId).toLowerCase() === "s3") {
    await resolveParamsForS3(endpointParams);
  }
  return endpointParams;
};

// node_modules/@smithy/middleware-endpoint/dist-es/endpointMiddleware.js
var endpointMiddleware = ({ config, instructions }) => {
  return (next, context) => async (args) => {
    if (config.isCustomEndpoint) {
      setFeature2(context, "ENDPOINT_OVERRIDE", "N");
    }
    const endpoint = await getEndpointFromInstructions(args.input, {
      getEndpointParameterInstructions() {
        return instructions;
      }
    }, { ...config }, context);
    context.endpointV2 = endpoint;
    context.authSchemes = endpoint.properties?.authSchemes;
    const authScheme = context.authSchemes?.[0];
    if (authScheme) {
      context["signing_region"] = authScheme.signingRegion;
      context["signing_service"] = authScheme.signingName;
      const smithyContext = getSmithyContext(context);
      const httpAuthOption = smithyContext?.selectedHttpAuthScheme?.httpAuthOption;
      if (httpAuthOption) {
        httpAuthOption.signingProperties = Object.assign(httpAuthOption.signingProperties || {}, {
          signing_region: authScheme.signingRegion,
          signingRegion: authScheme.signingRegion,
          signing_service: authScheme.signingName,
          signingName: authScheme.signingName,
          signingRegionSet: authScheme.signingRegionSet
        }, authScheme.properties);
      }
    }
    return next({
      ...args
    });
  };
};

// node_modules/@smithy/middleware-endpoint/dist-es/getEndpointPlugin.js
var endpointMiddlewareOptions = {
  step: "serialize",
  tags: ["ENDPOINT_PARAMETERS", "ENDPOINT_V2", "ENDPOINT"],
  name: "endpointV2Middleware",
  override: true,
  relation: "before",
  toMiddleware: serializerMiddlewareOption.name
};
var getEndpointPlugin = (config, instructions) => ({
  applyToStack: (clientStack) => {
    clientStack.addRelativeTo(endpointMiddleware({
      config,
      instructions
    }), endpointMiddlewareOptions);
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/resolveEndpointConfig.js
var resolveEndpointConfig = (input) => {
  const tls = input.tls ?? true;
  const { endpoint, useDualstackEndpoint, useFipsEndpoint } = input;
  const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await normalizeProvider(endpoint)()) : void 0;
  const isCustomEndpoint = !!endpoint;
  const resolvedConfig = Object.assign(input, {
    endpoint: customEndpointProvider,
    tls,
    isCustomEndpoint,
    useDualstackEndpoint: normalizeProvider(useDualstackEndpoint ?? false),
    useFipsEndpoint: normalizeProvider(useFipsEndpoint ?? false)
  });
  let configuredEndpointPromise = void 0;
  resolvedConfig.serviceConfiguredEndpoint = async () => {
    if (input.serviceId && !configuredEndpointPromise) {
      configuredEndpointPromise = getEndpointFromConfig(input.serviceId);
    }
    return configuredEndpointPromise;
  };
  return resolvedConfig;
};

// node_modules/@smithy/util-retry/dist-es/config.js
var RETRY_MODES;
(function(RETRY_MODES2) {
  RETRY_MODES2["STANDARD"] = "standard";
  RETRY_MODES2["ADAPTIVE"] = "adaptive";
})(RETRY_MODES || (RETRY_MODES = {}));
var DEFAULT_MAX_ATTEMPTS = 3;
var DEFAULT_RETRY_MODE = RETRY_MODES.STANDARD;

// node_modules/@smithy/service-error-classification/dist-es/constants.js
var THROTTLING_ERROR_CODES = [
  "BandwidthLimitExceeded",
  "EC2ThrottledException",
  "LimitExceededException",
  "PriorRequestNotComplete",
  "ProvisionedThroughputExceededException",
  "RequestLimitExceeded",
  "RequestThrottled",
  "RequestThrottledException",
  "SlowDown",
  "ThrottledException",
  "Throttling",
  "ThrottlingException",
  "TooManyRequestsException",
  "TransactionInProgressException"
];
var TRANSIENT_ERROR_CODES = ["TimeoutError", "RequestTimeout", "RequestTimeoutException"];
var TRANSIENT_ERROR_STATUS_CODES = [500, 502, 503, 504];
var NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"];
var NODEJS_NETWORK_ERROR_CODES = ["EHOSTUNREACH", "ENETUNREACH", "ENOTFOUND"];

// node_modules/@smithy/service-error-classification/dist-es/index.js
var isRetryableByTrait = (error) => error?.$retryable !== void 0;
var isClockSkewCorrectedError = (error) => error.$metadata?.clockSkewCorrected;
var isBrowserNetworkError = (error) => {
  const errorMessages = /* @__PURE__ */ new Set([
    "Failed to fetch",
    "NetworkError when attempting to fetch resource",
    "The Internet connection appears to be offline",
    "Load failed",
    "Network request failed"
  ]);
  const isValid = error && error instanceof TypeError;
  if (!isValid) {
    return false;
  }
  return errorMessages.has(error.message);
};
var isThrottlingError = (error) => error.$metadata?.httpStatusCode === 429 || THROTTLING_ERROR_CODES.includes(error.name) || error.$retryable?.throttling == true;
var isTransientError = (error, depth = 0) => isRetryableByTrait(error) || isClockSkewCorrectedError(error) || TRANSIENT_ERROR_CODES.includes(error.name) || NODEJS_TIMEOUT_ERROR_CODES.includes(error?.code || "") || NODEJS_NETWORK_ERROR_CODES.includes(error?.code || "") || TRANSIENT_ERROR_STATUS_CODES.includes(error.$metadata?.httpStatusCode || 0) || isBrowserNetworkError(error) || error.cause !== void 0 && depth <= 10 && isTransientError(error.cause, depth + 1);
var isServerError = (error) => {
  if (error.$metadata?.httpStatusCode !== void 0) {
    const statusCode = error.$metadata.httpStatusCode;
    if (500 <= statusCode && statusCode <= 599 && !isTransientError(error)) {
      return true;
    }
    return false;
  }
  return false;
};

// node_modules/@smithy/util-retry/dist-es/DefaultRateLimiter.js
var DefaultRateLimiter = class _DefaultRateLimiter {
  static setTimeoutFn = setTimeout;
  beta;
  minCapacity;
  minFillRate;
  scaleConstant;
  smooth;
  currentCapacity = 0;
  enabled = false;
  lastMaxRate = 0;
  measuredTxRate = 0;
  requestCount = 0;
  fillRate;
  lastThrottleTime;
  lastTimestamp = 0;
  lastTxRateBucket;
  maxCapacity;
  timeWindow = 0;
  constructor(options) {
    this.beta = options?.beta ?? 0.7;
    this.minCapacity = options?.minCapacity ?? 1;
    this.minFillRate = options?.minFillRate ?? 0.5;
    this.scaleConstant = options?.scaleConstant ?? 0.4;
    this.smooth = options?.smooth ?? 0.8;
    const currentTimeInSeconds = this.getCurrentTimeInSeconds();
    this.lastThrottleTime = currentTimeInSeconds;
    this.lastTxRateBucket = Math.floor(this.getCurrentTimeInSeconds());
    this.fillRate = this.minFillRate;
    this.maxCapacity = this.minCapacity;
  }
  getCurrentTimeInSeconds() {
    return Date.now() / 1e3;
  }
  async getSendToken() {
    return this.acquireTokenBucket(1);
  }
  async acquireTokenBucket(amount) {
    if (!this.enabled) {
      return;
    }
    this.refillTokenBucket();
    if (amount > this.currentCapacity) {
      const delay = (amount - this.currentCapacity) / this.fillRate * 1e3;
      await new Promise((resolve) => _DefaultRateLimiter.setTimeoutFn(resolve, delay));
    }
    this.currentCapacity = this.currentCapacity - amount;
  }
  refillTokenBucket() {
    const timestamp = this.getCurrentTimeInSeconds();
    if (!this.lastTimestamp) {
      this.lastTimestamp = timestamp;
      return;
    }
    const fillAmount = (timestamp - this.lastTimestamp) * this.fillRate;
    this.currentCapacity = Math.min(this.maxCapacity, this.currentCapacity + fillAmount);
    this.lastTimestamp = timestamp;
  }
  updateClientSendingRate(response) {
    let calculatedRate;
    this.updateMeasuredRate();
    if (isThrottlingError(response)) {
      const rateToUse = !this.enabled ? this.measuredTxRate : Math.min(this.measuredTxRate, this.fillRate);
      this.lastMaxRate = rateToUse;
      this.calculateTimeWindow();
      this.lastThrottleTime = this.getCurrentTimeInSeconds();
      calculatedRate = this.cubicThrottle(rateToUse);
      this.enableTokenBucket();
    } else {
      this.calculateTimeWindow();
      calculatedRate = this.cubicSuccess(this.getCurrentTimeInSeconds());
    }
    const newRate = Math.min(calculatedRate, 2 * this.measuredTxRate);
    this.updateTokenBucketRate(newRate);
  }
  calculateTimeWindow() {
    this.timeWindow = this.getPrecise(Math.pow(this.lastMaxRate * (1 - this.beta) / this.scaleConstant, 1 / 3));
  }
  cubicThrottle(rateToUse) {
    return this.getPrecise(rateToUse * this.beta);
  }
  cubicSuccess(timestamp) {
    return this.getPrecise(this.scaleConstant * Math.pow(timestamp - this.lastThrottleTime - this.timeWindow, 3) + this.lastMaxRate);
  }
  enableTokenBucket() {
    this.enabled = true;
  }
  updateTokenBucketRate(newRate) {
    this.refillTokenBucket();
    this.fillRate = Math.max(newRate, this.minFillRate);
    this.maxCapacity = Math.max(newRate, this.minCapacity);
    this.currentCapacity = Math.min(this.currentCapacity, this.maxCapacity);
  }
  updateMeasuredRate() {
    const t2 = this.getCurrentTimeInSeconds();
    const timeBucket = Math.floor(t2 * 2) / 2;
    this.requestCount++;
    if (timeBucket > this.lastTxRateBucket) {
      const currentRate = this.requestCount / (timeBucket - this.lastTxRateBucket);
      this.measuredTxRate = this.getPrecise(currentRate * this.smooth + this.measuredTxRate * (1 - this.smooth));
      this.requestCount = 0;
      this.lastTxRateBucket = timeBucket;
    }
  }
  getPrecise(num) {
    return parseFloat(num.toFixed(8));
  }
};

// node_modules/@smithy/util-retry/dist-es/constants.js
var DEFAULT_RETRY_DELAY_BASE = 100;
var MAXIMUM_RETRY_DELAY = 20 * 1e3;
var THROTTLING_RETRY_DELAY_BASE = 500;
var INITIAL_RETRY_TOKENS = 500;
var RETRY_COST = 5;
var TIMEOUT_RETRY_COST = 10;
var NO_RETRY_INCREMENT = 1;
var INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
var REQUEST_HEADER = "amz-sdk-request";

// node_modules/@smithy/util-retry/dist-es/defaultRetryBackoffStrategy.js
var getDefaultRetryBackoffStrategy = () => {
  let delayBase = DEFAULT_RETRY_DELAY_BASE;
  const computeNextBackoffDelay = (attempts) => {
    return Math.floor(Math.min(MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
  };
  const setDelayBase = (delay) => {
    delayBase = delay;
  };
  return {
    computeNextBackoffDelay,
    setDelayBase
  };
};

// node_modules/@smithy/util-retry/dist-es/defaultRetryToken.js
var createDefaultRetryToken = ({ retryDelay, retryCount, retryCost }) => {
  const getRetryCount = () => retryCount;
  const getRetryDelay = () => Math.min(MAXIMUM_RETRY_DELAY, retryDelay);
  const getRetryCost = () => retryCost;
  return {
    getRetryCount,
    getRetryDelay,
    getRetryCost
  };
};

// node_modules/@smithy/util-retry/dist-es/StandardRetryStrategy.js
var StandardRetryStrategy = class {
  maxAttempts;
  mode = RETRY_MODES.STANDARD;
  capacity = INITIAL_RETRY_TOKENS;
  retryBackoffStrategy = getDefaultRetryBackoffStrategy();
  maxAttemptsProvider;
  constructor(maxAttempts) {
    this.maxAttempts = maxAttempts;
    this.maxAttemptsProvider = typeof maxAttempts === "function" ? maxAttempts : async () => maxAttempts;
  }
  async acquireInitialRetryToken(retryTokenScope) {
    return createDefaultRetryToken({
      retryDelay: DEFAULT_RETRY_DELAY_BASE,
      retryCount: 0
    });
  }
  async refreshRetryTokenForRetry(token, errorInfo) {
    const maxAttempts = await this.getMaxAttempts();
    if (this.shouldRetry(token, errorInfo, maxAttempts)) {
      const errorType = errorInfo.errorType;
      this.retryBackoffStrategy.setDelayBase(errorType === "THROTTLING" ? THROTTLING_RETRY_DELAY_BASE : DEFAULT_RETRY_DELAY_BASE);
      const delayFromErrorType = this.retryBackoffStrategy.computeNextBackoffDelay(token.getRetryCount());
      const retryDelay = errorInfo.retryAfterHint ? Math.max(errorInfo.retryAfterHint.getTime() - Date.now() || 0, delayFromErrorType) : delayFromErrorType;
      const capacityCost = this.getCapacityCost(errorType);
      this.capacity -= capacityCost;
      return createDefaultRetryToken({
        retryDelay,
        retryCount: token.getRetryCount() + 1,
        retryCost: capacityCost
      });
    }
    throw new Error("No retry token available");
  }
  recordSuccess(token) {
    this.capacity = Math.max(INITIAL_RETRY_TOKENS, this.capacity + (token.getRetryCost() ?? NO_RETRY_INCREMENT));
  }
  getCapacity() {
    return this.capacity;
  }
  async getMaxAttempts() {
    try {
      return await this.maxAttemptsProvider();
    } catch (error) {
      console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
      return DEFAULT_MAX_ATTEMPTS;
    }
  }
  shouldRetry(tokenToRenew, errorInfo, maxAttempts) {
    const attempts = tokenToRenew.getRetryCount() + 1;
    return attempts < maxAttempts && this.capacity >= this.getCapacityCost(errorInfo.errorType) && this.isRetryableError(errorInfo.errorType);
  }
  getCapacityCost(errorType) {
    return errorType === "TRANSIENT" ? TIMEOUT_RETRY_COST : RETRY_COST;
  }
  isRetryableError(errorType) {
    return errorType === "THROTTLING" || errorType === "TRANSIENT";
  }
};

// node_modules/@smithy/util-retry/dist-es/AdaptiveRetryStrategy.js
var AdaptiveRetryStrategy = class {
  maxAttemptsProvider;
  rateLimiter;
  standardRetryStrategy;
  mode = RETRY_MODES.ADAPTIVE;
  constructor(maxAttemptsProvider, options) {
    this.maxAttemptsProvider = maxAttemptsProvider;
    const { rateLimiter } = options ?? {};
    this.rateLimiter = rateLimiter ?? new DefaultRateLimiter();
    this.standardRetryStrategy = new StandardRetryStrategy(maxAttemptsProvider);
  }
  async acquireInitialRetryToken(retryTokenScope) {
    await this.rateLimiter.getSendToken();
    return this.standardRetryStrategy.acquireInitialRetryToken(retryTokenScope);
  }
  async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
    this.rateLimiter.updateClientSendingRate(errorInfo);
    return this.standardRetryStrategy.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
  }
  recordSuccess(token) {
    this.rateLimiter.updateClientSendingRate({});
    this.standardRetryStrategy.recordSuccess(token);
  }
};

// node_modules/@smithy/middleware-retry/dist-es/util.js
var asSdkError = (error) => {
  if (error instanceof Error)
    return error;
  if (error instanceof Object)
    return Object.assign(new Error(), error);
  if (typeof error === "string")
    return new Error(error);
  return new Error(`AWS SDK error wrapper for ${error}`);
};

// node_modules/@smithy/middleware-retry/dist-es/configurations.js
var resolveRetryConfig = (input) => {
  const { retryStrategy, retryMode: _retryMode, maxAttempts: _maxAttempts } = input;
  const maxAttempts = normalizeProvider(_maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
  return Object.assign(input, {
    maxAttempts,
    retryStrategy: async () => {
      if (retryStrategy) {
        return retryStrategy;
      }
      const retryMode = await normalizeProvider(_retryMode)();
      if (retryMode === RETRY_MODES.ADAPTIVE) {
        return new AdaptiveRetryStrategy(maxAttempts);
      }
      return new StandardRetryStrategy(maxAttempts);
    }
  });
};

// node_modules/@smithy/middleware-retry/dist-es/isStreamingPayload/isStreamingPayload.browser.js
var isStreamingPayload = (request) => request?.body instanceof ReadableStream;

// node_modules/@smithy/middleware-retry/dist-es/retryMiddleware.js
var retryMiddleware = (options) => (next, context) => async (args) => {
  let retryStrategy = await options.retryStrategy();
  const maxAttempts = await options.maxAttempts();
  if (isRetryStrategyV2(retryStrategy)) {
    retryStrategy = retryStrategy;
    let retryToken = await retryStrategy.acquireInitialRetryToken(context["partition_id"]);
    let lastError = new Error();
    let attempts = 0;
    let totalRetryDelay = 0;
    const { request } = args;
    const isRequest = HttpRequest.isInstance(request);
    if (isRequest) {
      request.headers[INVOCATION_ID_HEADER] = v4();
    }
    while (true) {
      try {
        if (isRequest) {
          request.headers[REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
        }
        const { response, output } = await next(args);
        retryStrategy.recordSuccess(retryToken);
        output.$metadata.attempts = attempts + 1;
        output.$metadata.totalRetryDelay = totalRetryDelay;
        return { response, output };
      } catch (e2) {
        const retryErrorInfo = getRetryErrorInfo(e2);
        lastError = asSdkError(e2);
        if (isRequest && isStreamingPayload(request)) {
          (context.logger instanceof NoOpLogger ? console : context.logger)?.warn("An error was encountered in a non-retryable streaming request.");
          throw lastError;
        }
        try {
          retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
        } catch (refreshError) {
          if (!lastError.$metadata) {
            lastError.$metadata = {};
          }
          lastError.$metadata.attempts = attempts + 1;
          lastError.$metadata.totalRetryDelay = totalRetryDelay;
          throw lastError;
        }
        attempts = retryToken.getRetryCount();
        const delay = retryToken.getRetryDelay();
        totalRetryDelay += delay;
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  } else {
    retryStrategy = retryStrategy;
    if (retryStrategy?.mode)
      context.userAgent = [...context.userAgent || [], ["cfg/retry-mode", retryStrategy.mode]];
    return retryStrategy.retry(next, args);
  }
};
var isRetryStrategyV2 = (retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" && typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" && typeof retryStrategy.recordSuccess !== "undefined";
var getRetryErrorInfo = (error) => {
  const errorInfo = {
    error,
    errorType: getRetryErrorType(error)
  };
  const retryAfterHint = getRetryAfterHint(error.$response);
  if (retryAfterHint) {
    errorInfo.retryAfterHint = retryAfterHint;
  }
  return errorInfo;
};
var getRetryErrorType = (error) => {
  if (isThrottlingError(error))
    return "THROTTLING";
  if (isTransientError(error))
    return "TRANSIENT";
  if (isServerError(error))
    return "SERVER_ERROR";
  return "CLIENT_ERROR";
};
var retryMiddlewareOptions = {
  name: "retryMiddleware",
  tags: ["RETRY"],
  step: "finalizeRequest",
  priority: "high",
  override: true
};
var getRetryPlugin = (options) => ({
  applyToStack: (clientStack) => {
    clientStack.add(retryMiddleware(options), retryMiddlewareOptions);
  }
});
var getRetryAfterHint = (response) => {
  if (!HttpResponse.isInstance(response))
    return;
  const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
  if (!retryAfterHeaderName)
    return;
  const retryAfter = response.headers[retryAfterHeaderName];
  const retryAfterSeconds = Number(retryAfter);
  if (!Number.isNaN(retryAfterSeconds))
    return new Date(retryAfterSeconds * 1e3);
  const retryAfterDate = new Date(retryAfter);
  return retryAfterDate;
};

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/signature-v4-crt-container.js
var signatureV4CrtContainer = {
  CrtSignerV4: null
};

// node_modules/@aws-sdk/signature-v4-multi-region/dist-es/SignatureV4MultiRegion.js
var SignatureV4MultiRegion = class {
  sigv4aSigner;
  sigv4Signer;
  signerOptions;
  static sigv4aDependency() {
    if (typeof signatureV4CrtContainer.CrtSignerV4 === "function") {
      return "crt";
    } else if (typeof signatureV4aContainer.SignatureV4a === "function") {
      return "js";
    }
    return "none";
  }
  constructor(options) {
    this.sigv4Signer = new SignatureV4S3Express(options);
    this.signerOptions = options;
  }
  async sign(requestToSign, options = {}) {
    if (options.signingRegion === "*") {
      return this.getSigv4aSigner().sign(requestToSign, options);
    }
    return this.sigv4Signer.sign(requestToSign, options);
  }
  async signWithCredentials(requestToSign, credentials, options = {}) {
    if (options.signingRegion === "*") {
      const signer = this.getSigv4aSigner();
      const CrtSignerV4 = signatureV4CrtContainer.CrtSignerV4;
      if (CrtSignerV4 && signer instanceof CrtSignerV4) {
        return signer.signWithCredentials(requestToSign, credentials, options);
      } else {
        throw new Error(`signWithCredentials with signingRegion '*' is only supported when using the CRT dependency @aws-sdk/signature-v4-crt. Please check whether you have installed the "@aws-sdk/signature-v4-crt" package explicitly. You must also register the package by calling [require("@aws-sdk/signature-v4-crt");] or an ESM equivalent such as [import "@aws-sdk/signature-v4-crt";]. For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt`);
      }
    }
    return this.sigv4Signer.signWithCredentials(requestToSign, credentials, options);
  }
  async presign(originalRequest, options = {}) {
    if (options.signingRegion === "*") {
      const signer = this.getSigv4aSigner();
      const CrtSignerV4 = signatureV4CrtContainer.CrtSignerV4;
      if (CrtSignerV4 && signer instanceof CrtSignerV4) {
        return signer.presign(originalRequest, options);
      } else {
        throw new Error(`presign with signingRegion '*' is only supported when using the CRT dependency @aws-sdk/signature-v4-crt. Please check whether you have installed the "@aws-sdk/signature-v4-crt" package explicitly. You must also register the package by calling [require("@aws-sdk/signature-v4-crt");] or an ESM equivalent such as [import "@aws-sdk/signature-v4-crt";]. For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt`);
      }
    }
    return this.sigv4Signer.presign(originalRequest, options);
  }
  async presignWithCredentials(originalRequest, credentials, options = {}) {
    if (options.signingRegion === "*") {
      throw new Error("Method presignWithCredentials is not supported for [signingRegion=*].");
    }
    return this.sigv4Signer.presignWithCredentials(originalRequest, credentials, options);
  }
  getSigv4aSigner() {
    if (!this.sigv4aSigner) {
      const CrtSignerV4 = signatureV4CrtContainer.CrtSignerV4;
      const JsSigV4aSigner = signatureV4aContainer.SignatureV4a;
      if (this.signerOptions.runtime === "node") {
        if (!CrtSignerV4 && !JsSigV4aSigner) {
          throw new Error("Neither CRT nor JS SigV4a implementation is available. Please load either @aws-sdk/signature-v4-crt or @aws-sdk/signature-v4a. For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt");
        }
        if (CrtSignerV4 && typeof CrtSignerV4 === "function") {
          this.sigv4aSigner = new CrtSignerV4({
            ...this.signerOptions,
            signingAlgorithm: 1
          });
        } else if (JsSigV4aSigner && typeof JsSigV4aSigner === "function") {
          this.sigv4aSigner = new JsSigV4aSigner({
            ...this.signerOptions
          });
        } else {
          throw new Error("Available SigV4a implementation is not a valid constructor. Please ensure you've properly imported @aws-sdk/signature-v4-crt or @aws-sdk/signature-v4a.For more information please go to https://github.com/aws/aws-sdk-js-v3#functionality-requiring-aws-common-runtime-crt");
        }
      } else {
        if (!JsSigV4aSigner || typeof JsSigV4aSigner !== "function") {
          throw new Error("JS SigV4a implementation is not available or not a valid constructor. Please check whether you have installed the @aws-sdk/signature-v4a package explicitly. The CRT implementation is not available for browsers. You must also register the package by calling [require('@aws-sdk/signature-v4a');] or an ESM equivalent such as [import '@aws-sdk/signature-v4a';]. For more information please go to https://github.com/aws/aws-sdk-js-v3#using-javascript-non-crt-implementation-of-sigv4a");
        }
        this.sigv4aSigner = new JsSigV4aSigner({
          ...this.signerOptions
        });
      }
    }
    return this.sigv4aSigner;
  }
};

// node_modules/@aws-sdk/client-s3/dist-es/endpoint/ruleset.js
var cs = "required";
var ct = "type";
var cu = "rules";
var cv = "conditions";
var cw = "fn";
var cx = "argv";
var cy = "ref";
var cz = "assign";
var cA = "url";
var cB = "properties";
var cC = "backend";
var cD = "authSchemes";
var cE = "disableDoubleEncoding";
var cF = "signingName";
var cG = "signingRegion";
var cH = "headers";
var cI = "signingRegionSet";
var a = 6;
var b = false;
var c = true;
var d = "isSet";
var e = "booleanEquals";
var f = "error";
var g = "aws.partition";
var h = "stringEquals";
var i = "getAttr";
var j = "name";
var k = "substring";
var l = "bucketSuffix";
var m = "parseURL";
var n = "endpoint";
var o = "tree";
var p = "aws.isVirtualHostableS3Bucket";
var q = "{url#scheme}://{Bucket}.{url#authority}{url#path}";
var r = "not";
var s = "accessPointSuffix";
var t = "{url#scheme}://{url#authority}{url#path}";
var u = "hardwareType";
var v = "regionPrefix";
var w = "bucketAliasSuffix";
var x = "outpostId";
var y = "isValidHostLabel";
var z = "sigv4a";
var A = "s3-outposts";
var B = "s3";
var C = "{url#scheme}://{url#authority}{url#normalizedPath}{Bucket}";
var D = "https://{Bucket}.s3-accelerate.{partitionResult#dnsSuffix}";
var E = "https://{Bucket}.s3.{partitionResult#dnsSuffix}";
var F = "aws.parseArn";
var G = "bucketArn";
var H = "arnType";
var I = "";
var J = "s3-object-lambda";
var K = "accesspoint";
var L = "accessPointName";
var M = "{url#scheme}://{accessPointName}-{bucketArn#accountId}.{url#authority}{url#path}";
var N = "mrapPartition";
var O = "outpostType";
var P = "arnPrefix";
var Q = "{url#scheme}://{url#authority}{url#normalizedPath}{uri_encoded_bucket}";
var R = "https://s3.{partitionResult#dnsSuffix}/{uri_encoded_bucket}";
var S = "https://s3.{partitionResult#dnsSuffix}";
var T = { [cs]: false, [ct]: "string" };
var U = { [cs]: true, "default": false, [ct]: "boolean" };
var V = { [cs]: false, [ct]: "boolean" };
var W = { [cw]: e, [cx]: [{ [cy]: "Accelerate" }, true] };
var X = { [cw]: e, [cx]: [{ [cy]: "UseFIPS" }, true] };
var Y = { [cw]: e, [cx]: [{ [cy]: "UseDualStack" }, true] };
var Z = { [cw]: d, [cx]: [{ [cy]: "Endpoint" }] };
var aa = { [cw]: g, [cx]: [{ [cy]: "Region" }], [cz]: "partitionResult" };
var ab = { [cw]: h, [cx]: [{ [cw]: i, [cx]: [{ [cy]: "partitionResult" }, j] }, "aws-cn"] };
var ac = { [cw]: d, [cx]: [{ [cy]: "Bucket" }] };
var ad = { [cy]: "Bucket" };
var ae = { [cv]: [W], [f]: "S3Express does not support S3 Accelerate.", [ct]: f };
var af = { [cv]: [Z, { [cw]: m, [cx]: [{ [cy]: "Endpoint" }], [cz]: "url" }], [cu]: [{ [cv]: [{ [cw]: d, [cx]: [{ [cy]: "DisableS3ExpressSessionAuth" }] }, { [cw]: e, [cx]: [{ [cy]: "DisableS3ExpressSessionAuth" }, true] }], [cu]: [{ [cv]: [{ [cw]: e, [cx]: [{ [cw]: i, [cx]: [{ [cy]: "url" }, "isIp"] }, true] }], [cu]: [{ [cv]: [{ [cw]: "uriEncode", [cx]: [ad], [cz]: "uri_encoded_bucket" }], [cu]: [{ [n]: { [cA]: "{url#scheme}://{url#authority}/{uri_encoded_bucket}{url#path}", [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }], [ct]: o }], [ct]: o }, { [cv]: [{ [cw]: p, [cx]: [ad, false] }], [cu]: [{ [n]: { [cA]: q, [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }], [ct]: o }, { [f]: "S3Express bucket name is not a valid virtual hostable name.", [ct]: f }], [ct]: o }, { [cv]: [{ [cw]: e, [cx]: [{ [cw]: i, [cx]: [{ [cy]: "url" }, "isIp"] }, true] }], [cu]: [{ [cv]: [{ [cw]: "uriEncode", [cx]: [ad], [cz]: "uri_encoded_bucket" }], [cu]: [{ [n]: { [cA]: "{url#scheme}://{url#authority}/{uri_encoded_bucket}{url#path}", [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4-s3express", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }], [ct]: o }], [ct]: o }, { [cv]: [{ [cw]: p, [cx]: [ad, false] }], [cu]: [{ [n]: { [cA]: q, [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4-s3express", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }], [ct]: o }, { [f]: "S3Express bucket name is not a valid virtual hostable name.", [ct]: f }], [ct]: o };
var ag = { [cw]: m, [cx]: [{ [cy]: "Endpoint" }], [cz]: "url" };
var ah = { [cw]: e, [cx]: [{ [cw]: i, [cx]: [{ [cy]: "url" }, "isIp"] }, true] };
var ai = { [cy]: "url" };
var aj = { [cw]: "uriEncode", [cx]: [ad], [cz]: "uri_encoded_bucket" };
var ak = { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: "s3express", [cG]: "{Region}" }] };
var al = {};
var am = { [cw]: p, [cx]: [ad, false] };
var an = { [f]: "S3Express bucket name is not a valid virtual hostable name.", [ct]: f };
var ao = { [cw]: d, [cx]: [{ [cy]: "UseS3ExpressControlEndpoint" }] };
var ap = { [cw]: e, [cx]: [{ [cy]: "UseS3ExpressControlEndpoint" }, true] };
var aq = { [cw]: r, [cx]: [Z] };
var ar = { [cw]: e, [cx]: [{ [cy]: "UseDualStack" }, false] };
var as = { [cw]: e, [cx]: [{ [cy]: "UseFIPS" }, false] };
var at = { [f]: "Unrecognized S3Express bucket name format.", [ct]: f };
var au = { [cw]: r, [cx]: [ac] };
var av = { [cy]: u };
var aw = { [cv]: [aq], [f]: "Expected a endpoint to be specified but no endpoint was found", [ct]: f };
var ax = { [cD]: [{ [cE]: true, [j]: z, [cF]: A, [cI]: ["*"] }, { [cE]: true, [j]: "sigv4", [cF]: A, [cG]: "{Region}" }] };
var ay = { [cw]: e, [cx]: [{ [cy]: "ForcePathStyle" }, false] };
var az = { [cy]: "ForcePathStyle" };
var aA = { [cw]: e, [cx]: [{ [cy]: "Accelerate" }, false] };
var aB = { [cw]: h, [cx]: [{ [cy]: "Region" }, "aws-global"] };
var aC = { [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: B, [cG]: "us-east-1" }] };
var aD = { [cw]: r, [cx]: [aB] };
var aE = { [cw]: e, [cx]: [{ [cy]: "UseGlobalEndpoint" }, true] };
var aF = { [cA]: "https://{Bucket}.s3-fips.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: { [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: B, [cG]: "{Region}" }] }, [cH]: {} };
var aG = { [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: B, [cG]: "{Region}" }] };
var aH = { [cw]: e, [cx]: [{ [cy]: "UseGlobalEndpoint" }, false] };
var aI = { [cA]: "https://{Bucket}.s3-fips.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var aJ = { [cA]: "https://{Bucket}.s3-accelerate.dualstack.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var aK = { [cA]: "https://{Bucket}.s3.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var aL = { [cw]: e, [cx]: [{ [cw]: i, [cx]: [ai, "isIp"] }, false] };
var aM = { [cA]: C, [cB]: aG, [cH]: {} };
var aN = { [cA]: q, [cB]: aG, [cH]: {} };
var aO = { [n]: aN, [ct]: n };
var aP = { [cA]: D, [cB]: aG, [cH]: {} };
var aQ = { [cA]: "https://{Bucket}.s3.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var aR = { [f]: "Invalid region: region was not a valid DNS name.", [ct]: f };
var aS = { [cy]: G };
var aT = { [cy]: H };
var aU = { [cw]: i, [cx]: [aS, "service"] };
var aV = { [cy]: L };
var aW = { [cv]: [Y], [f]: "S3 Object Lambda does not support Dual-stack", [ct]: f };
var aX = { [cv]: [W], [f]: "S3 Object Lambda does not support S3 Accelerate", [ct]: f };
var aY = { [cv]: [{ [cw]: d, [cx]: [{ [cy]: "DisableAccessPoints" }] }, { [cw]: e, [cx]: [{ [cy]: "DisableAccessPoints" }, true] }], [f]: "Access points are not supported for this operation", [ct]: f };
var aZ = { [cv]: [{ [cw]: d, [cx]: [{ [cy]: "UseArnRegion" }] }, { [cw]: e, [cx]: [{ [cy]: "UseArnRegion" }, false] }, { [cw]: r, [cx]: [{ [cw]: h, [cx]: [{ [cw]: i, [cx]: [aS, "region"] }, "{Region}"] }] }], [f]: "Invalid configuration: region from ARN `{bucketArn#region}` does not match client region `{Region}` and UseArnRegion is `false`", [ct]: f };
var ba = { [cw]: i, [cx]: [{ [cy]: "bucketPartition" }, j] };
var bb = { [cw]: i, [cx]: [aS, "accountId"] };
var bc = { [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: J, [cG]: "{bucketArn#region}" }] };
var bd = { [f]: "Invalid ARN: The access point name may only contain a-z, A-Z, 0-9 and `-`. Found: `{accessPointName}`", [ct]: f };
var be = { [f]: "Invalid ARN: The account id may only contain a-z, A-Z, 0-9 and `-`. Found: `{bucketArn#accountId}`", [ct]: f };
var bf = { [f]: "Invalid region in ARN: `{bucketArn#region}` (invalid DNS name)", [ct]: f };
var bg = { [f]: "Client was configured for partition `{partitionResult#name}` but ARN (`{Bucket}`) has `{bucketPartition#name}`", [ct]: f };
var bh = { [f]: "Invalid ARN: The ARN may only contain a single resource component after `accesspoint`.", [ct]: f };
var bi = { [f]: "Invalid ARN: Expected a resource of the format `accesspoint:<accesspoint name>` but no name was provided", [ct]: f };
var bj = { [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: B, [cG]: "{bucketArn#region}" }] };
var bk = { [cD]: [{ [cE]: true, [j]: z, [cF]: A, [cI]: ["*"] }, { [cE]: true, [j]: "sigv4", [cF]: A, [cG]: "{bucketArn#region}" }] };
var bl = { [cw]: F, [cx]: [ad] };
var bm = { [cA]: "https://s3-fips.dualstack.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aG, [cH]: {} };
var bn = { [cA]: "https://s3-fips.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aG, [cH]: {} };
var bo = { [cA]: "https://s3.dualstack.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aG, [cH]: {} };
var bp = { [cA]: Q, [cB]: aG, [cH]: {} };
var bq = { [cA]: "https://s3.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aG, [cH]: {} };
var br = { [cy]: "UseObjectLambdaEndpoint" };
var bs = { [cD]: [{ [cE]: true, [j]: "sigv4", [cF]: J, [cG]: "{Region}" }] };
var bt = { [cA]: "https://s3-fips.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var bu = { [cA]: "https://s3-fips.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var bv = { [cA]: "https://s3.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var bw = { [cA]: t, [cB]: aG, [cH]: {} };
var bx = { [cA]: "https://s3.{Region}.{partitionResult#dnsSuffix}", [cB]: aG, [cH]: {} };
var by = [{ [cy]: "Region" }];
var bz = [{ [cy]: "Endpoint" }];
var bA = [ad];
var bB = [W];
var bC = [Z, ag];
var bD = [{ [cw]: d, [cx]: [{ [cy]: "DisableS3ExpressSessionAuth" }] }, { [cw]: e, [cx]: [{ [cy]: "DisableS3ExpressSessionAuth" }, true] }];
var bE = [aj];
var bF = [am];
var bG = [aa];
var bH = [X, Y];
var bI = [X, ar];
var bJ = [as, Y];
var bK = [as, ar];
var bL = [{ [cw]: k, [cx]: [ad, 6, 14, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 14, 16, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bM = [{ [cv]: [X, Y], [n]: { [cA]: "https://{Bucket}.s3express-fips-{s3expressAvailabilityZoneId}.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: {} }, [ct]: n }, { [cv]: bI, [n]: { [cA]: "https://{Bucket}.s3express-fips-{s3expressAvailabilityZoneId}.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: {} }, [ct]: n }, { [cv]: bJ, [n]: { [cA]: "https://{Bucket}.s3express-{s3expressAvailabilityZoneId}.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: {} }, [ct]: n }, { [cv]: bK, [n]: { [cA]: "https://{Bucket}.s3express-{s3expressAvailabilityZoneId}.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: {} }, [ct]: n }];
var bN = [{ [cw]: k, [cx]: [ad, 6, 15, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 15, 17, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bO = [{ [cw]: k, [cx]: [ad, 6, 19, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 19, 21, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bP = [{ [cw]: k, [cx]: [ad, 6, 20, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 20, 22, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bQ = [{ [cw]: k, [cx]: [ad, 6, 26, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 26, 28, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bR = [{ [cv]: [X, Y], [n]: { [cA]: "https://{Bucket}.s3express-fips-{s3expressAvailabilityZoneId}.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4-s3express", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }, { [cv]: bI, [n]: { [cA]: "https://{Bucket}.s3express-fips-{s3expressAvailabilityZoneId}.{Region}.{partitionResult#dnsSuffix}", [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4-s3express", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }, { [cv]: bJ, [n]: { [cA]: "https://{Bucket}.s3express-{s3expressAvailabilityZoneId}.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4-s3express", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }, { [cv]: bK, [n]: { [cA]: "https://{Bucket}.s3express-{s3expressAvailabilityZoneId}.{Region}.{partitionResult#dnsSuffix}", [cB]: { [cC]: "S3Express", [cD]: [{ [cE]: true, [j]: "sigv4-s3express", [cF]: "s3express", [cG]: "{Region}" }] }, [cH]: {} }, [ct]: n }];
var bS = [ad, 0, 7, true];
var bT = [{ [cw]: k, [cx]: [ad, 7, 15, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 15, 17, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bU = [{ [cw]: k, [cx]: [ad, 7, 16, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 16, 18, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bV = [{ [cw]: k, [cx]: [ad, 7, 20, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 20, 22, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bW = [{ [cw]: k, [cx]: [ad, 7, 21, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 21, 23, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bX = [{ [cw]: k, [cx]: [ad, 7, 27, true], [cz]: "s3expressAvailabilityZoneId" }, { [cw]: k, [cx]: [ad, 27, 29, true], [cz]: "s3expressAvailabilityZoneDelim" }, { [cw]: h, [cx]: [{ [cy]: "s3expressAvailabilityZoneDelim" }, "--"] }];
var bY = [ac];
var bZ = [{ [cw]: y, [cx]: [{ [cy]: x }, false] }];
var ca = [{ [cw]: h, [cx]: [{ [cy]: v }, "beta"] }];
var cb = ["*"];
var cc = [{ [cw]: y, [cx]: [{ [cy]: "Region" }, false] }];
var cd = [{ [cw]: h, [cx]: [{ [cy]: "Region" }, "us-east-1"] }];
var ce = [{ [cw]: h, [cx]: [aT, K] }];
var cf = [{ [cw]: i, [cx]: [aS, "resourceId[1]"], [cz]: L }, { [cw]: r, [cx]: [{ [cw]: h, [cx]: [aV, I] }] }];
var cg = [aS, "resourceId[1]"];
var ch = [Y];
var ci = [{ [cw]: r, [cx]: [{ [cw]: h, [cx]: [{ [cw]: i, [cx]: [aS, "region"] }, I] }] }];
var cj = [{ [cw]: r, [cx]: [{ [cw]: d, [cx]: [{ [cw]: i, [cx]: [aS, "resourceId[2]"] }] }] }];
var ck = [aS, "resourceId[2]"];
var cl = [{ [cw]: g, [cx]: [{ [cw]: i, [cx]: [aS, "region"] }], [cz]: "bucketPartition" }];
var cm = [{ [cw]: h, [cx]: [ba, { [cw]: i, [cx]: [{ [cy]: "partitionResult" }, j] }] }];
var cn = [{ [cw]: y, [cx]: [{ [cw]: i, [cx]: [aS, "region"] }, true] }];
var co = [{ [cw]: y, [cx]: [bb, false] }];
var cp = [{ [cw]: y, [cx]: [aV, false] }];
var cq = [X];
var cr = [{ [cw]: y, [cx]: [{ [cy]: "Region" }, true] }];
var _data = { version: "1.0", parameters: { Bucket: T, Region: T, UseFIPS: U, UseDualStack: U, Endpoint: T, ForcePathStyle: U, Accelerate: U, UseGlobalEndpoint: U, UseObjectLambdaEndpoint: V, Key: T, Prefix: T, CopySource: T, DisableAccessPoints: V, DisableMultiRegionAccessPoints: U, UseArnRegion: V, UseS3ExpressControlEndpoint: V, DisableS3ExpressSessionAuth: V }, [cu]: [{ [cv]: [{ [cw]: d, [cx]: by }], [cu]: [{ [cv]: [W, X], error: "Accelerate cannot be used with FIPS", [ct]: f }, { [cv]: [Y, Z], error: "Cannot set dual-stack in combination with a custom endpoint.", [ct]: f }, { [cv]: [Z, X], error: "A custom endpoint cannot be combined with FIPS", [ct]: f }, { [cv]: [Z, W], error: "A custom endpoint cannot be combined with S3 Accelerate", [ct]: f }, { [cv]: [X, aa, ab], error: "Partition does not support FIPS", [ct]: f }, { [cv]: [ac, { [cw]: k, [cx]: [ad, 0, a, c], [cz]: l }, { [cw]: h, [cx]: [{ [cy]: l }, "--x-s3"] }], [cu]: [ae, af, { [cv]: [ao, ap], [cu]: [{ [cv]: bG, [cu]: [{ [cv]: [aj, aq], [cu]: [{ [cv]: bH, endpoint: { [cA]: "https://s3express-control-fips.dualstack.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bI, endpoint: { [cA]: "https://s3express-control-fips.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bJ, endpoint: { [cA]: "https://s3express-control.dualstack.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bK, endpoint: { [cA]: "https://s3express-control.{Region}.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: ak, [cH]: al }, [ct]: n }], [ct]: o }], [ct]: o }], [ct]: o }, { [cv]: bF, [cu]: [{ [cv]: bG, [cu]: [{ [cv]: bD, [cu]: [{ [cv]: bL, [cu]: bM, [ct]: o }, { [cv]: bN, [cu]: bM, [ct]: o }, { [cv]: bO, [cu]: bM, [ct]: o }, { [cv]: bP, [cu]: bM, [ct]: o }, { [cv]: bQ, [cu]: bM, [ct]: o }, at], [ct]: o }, { [cv]: bL, [cu]: bR, [ct]: o }, { [cv]: bN, [cu]: bR, [ct]: o }, { [cv]: bO, [cu]: bR, [ct]: o }, { [cv]: bP, [cu]: bR, [ct]: o }, { [cv]: bQ, [cu]: bR, [ct]: o }, at], [ct]: o }], [ct]: o }, an], [ct]: o }, { [cv]: [ac, { [cw]: k, [cx]: bS, [cz]: s }, { [cw]: h, [cx]: [{ [cy]: s }, "--xa-s3"] }], [cu]: [ae, af, { [cv]: bF, [cu]: [{ [cv]: bG, [cu]: [{ [cv]: bD, [cu]: [{ [cv]: bT, [cu]: bM, [ct]: o }, { [cv]: bU, [cu]: bM, [ct]: o }, { [cv]: bV, [cu]: bM, [ct]: o }, { [cv]: bW, [cu]: bM, [ct]: o }, { [cv]: bX, [cu]: bM, [ct]: o }, at], [ct]: o }, { [cv]: bT, [cu]: bR, [ct]: o }, { [cv]: bU, [cu]: bR, [ct]: o }, { [cv]: bV, [cu]: bR, [ct]: o }, { [cv]: bW, [cu]: bR, [ct]: o }, { [cv]: bX, [cu]: bR, [ct]: o }, at], [ct]: o }], [ct]: o }, an], [ct]: o }, { [cv]: [au, ao, ap], [cu]: [{ [cv]: bG, [cu]: [{ [cv]: bC, endpoint: { [cA]: t, [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bH, endpoint: { [cA]: "https://s3express-control-fips.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bI, endpoint: { [cA]: "https://s3express-control-fips.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bJ, endpoint: { [cA]: "https://s3express-control.dualstack.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: al }, [ct]: n }, { [cv]: bK, endpoint: { [cA]: "https://s3express-control.{Region}.{partitionResult#dnsSuffix}", [cB]: ak, [cH]: al }, [ct]: n }], [ct]: o }], [ct]: o }, { [cv]: [ac, { [cw]: k, [cx]: [ad, 49, 50, c], [cz]: u }, { [cw]: k, [cx]: [ad, 8, 12, c], [cz]: v }, { [cw]: k, [cx]: bS, [cz]: w }, { [cw]: k, [cx]: [ad, 32, 49, c], [cz]: x }, { [cw]: g, [cx]: by, [cz]: "regionPartition" }, { [cw]: h, [cx]: [{ [cy]: w }, "--op-s3"] }], [cu]: [{ [cv]: bZ, [cu]: [{ [cv]: [{ [cw]: h, [cx]: [av, "e"] }], [cu]: [{ [cv]: ca, [cu]: [aw, { [cv]: bC, endpoint: { [cA]: "https://{Bucket}.ec2.{url#authority}", [cB]: ax, [cH]: al }, [ct]: n }], [ct]: o }, { endpoint: { [cA]: "https://{Bucket}.ec2.s3-outposts.{Region}.{regionPartition#dnsSuffix}", [cB]: ax, [cH]: al }, [ct]: n }], [ct]: o }, { [cv]: [{ [cw]: h, [cx]: [av, "o"] }], [cu]: [{ [cv]: ca, [cu]: [aw, { [cv]: bC, endpoint: { [cA]: "https://{Bucket}.op-{outpostId}.{url#authority}", [cB]: ax, [cH]: al }, [ct]: n }], [ct]: o }, { endpoint: { [cA]: "https://{Bucket}.op-{outpostId}.s3-outposts.{Region}.{regionPartition#dnsSuffix}", [cB]: ax, [cH]: al }, [ct]: n }], [ct]: o }, { error: 'Unrecognized hardware type: "Expected hardware type o or e but got {hardwareType}"', [ct]: f }], [ct]: o }, { error: "Invalid ARN: The outpost Id must only contain a-z, A-Z, 0-9 and `-`.", [ct]: f }], [ct]: o }, { [cv]: bY, [cu]: [{ [cv]: [Z, { [cw]: r, [cx]: [{ [cw]: d, [cx]: [{ [cw]: m, [cx]: bz }] }] }], error: "Custom endpoint `{Endpoint}` was not a valid URI", [ct]: f }, { [cv]: [ay, am], [cu]: [{ [cv]: bG, [cu]: [{ [cv]: cc, [cu]: [{ [cv]: [W, ab], error: "S3 Accelerate cannot be used in this region", [ct]: f }, { [cv]: [Y, X, aA, aq, aB], endpoint: { [cA]: "https://{Bucket}.s3-fips.dualstack.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [Y, X, aA, aq, aD, aE], [cu]: [{ endpoint: aF, [ct]: n }], [ct]: o }, { [cv]: [Y, X, aA, aq, aD, aH], endpoint: aF, [ct]: n }, { [cv]: [ar, X, aA, aq, aB], endpoint: { [cA]: "https://{Bucket}.s3-fips.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, X, aA, aq, aD, aE], [cu]: [{ endpoint: aI, [ct]: n }], [ct]: o }, { [cv]: [ar, X, aA, aq, aD, aH], endpoint: aI, [ct]: n }, { [cv]: [Y, as, W, aq, aB], endpoint: { [cA]: "https://{Bucket}.s3-accelerate.dualstack.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [Y, as, W, aq, aD, aE], [cu]: [{ endpoint: aJ, [ct]: n }], [ct]: o }, { [cv]: [Y, as, W, aq, aD, aH], endpoint: aJ, [ct]: n }, { [cv]: [Y, as, aA, aq, aB], endpoint: { [cA]: "https://{Bucket}.s3.dualstack.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [Y, as, aA, aq, aD, aE], [cu]: [{ endpoint: aK, [ct]: n }], [ct]: o }, { [cv]: [Y, as, aA, aq, aD, aH], endpoint: aK, [ct]: n }, { [cv]: [ar, as, aA, Z, ag, ah, aB], endpoint: { [cA]: C, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, as, aA, Z, ag, aL, aB], endpoint: { [cA]: q, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, as, aA, Z, ag, ah, aD, aE], [cu]: [{ [cv]: cd, endpoint: aM, [ct]: n }, { endpoint: aM, [ct]: n }], [ct]: o }, { [cv]: [ar, as, aA, Z, ag, aL, aD, aE], [cu]: [{ [cv]: cd, endpoint: aN, [ct]: n }, aO], [ct]: o }, { [cv]: [ar, as, aA, Z, ag, ah, aD, aH], endpoint: aM, [ct]: n }, { [cv]: [ar, as, aA, Z, ag, aL, aD, aH], endpoint: aN, [ct]: n }, { [cv]: [ar, as, W, aq, aB], endpoint: { [cA]: D, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, as, W, aq, aD, aE], [cu]: [{ [cv]: cd, endpoint: aP, [ct]: n }, { endpoint: aP, [ct]: n }], [ct]: o }, { [cv]: [ar, as, W, aq, aD, aH], endpoint: aP, [ct]: n }, { [cv]: [ar, as, aA, aq, aB], endpoint: { [cA]: E, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, as, aA, aq, aD, aE], [cu]: [{ [cv]: cd, endpoint: { [cA]: E, [cB]: aG, [cH]: al }, [ct]: n }, { endpoint: aQ, [ct]: n }], [ct]: o }, { [cv]: [ar, as, aA, aq, aD, aH], endpoint: aQ, [ct]: n }], [ct]: o }, aR], [ct]: o }], [ct]: o }, { [cv]: [Z, ag, { [cw]: h, [cx]: [{ [cw]: i, [cx]: [ai, "scheme"] }, "http"] }, { [cw]: p, [cx]: [ad, c] }, ay, as, ar, aA], [cu]: [{ [cv]: bG, [cu]: [{ [cv]: cc, [cu]: [aO], [ct]: o }, aR], [ct]: o }], [ct]: o }, { [cv]: [ay, { [cw]: F, [cx]: bA, [cz]: G }], [cu]: [{ [cv]: [{ [cw]: i, [cx]: [aS, "resourceId[0]"], [cz]: H }, { [cw]: r, [cx]: [{ [cw]: h, [cx]: [aT, I] }] }], [cu]: [{ [cv]: [{ [cw]: h, [cx]: [aU, J] }], [cu]: [{ [cv]: ce, [cu]: [{ [cv]: cf, [cu]: [aW, aX, { [cv]: ci, [cu]: [aY, { [cv]: cj, [cu]: [aZ, { [cv]: cl, [cu]: [{ [cv]: bG, [cu]: [{ [cv]: cm, [cu]: [{ [cv]: cn, [cu]: [{ [cv]: [{ [cw]: h, [cx]: [bb, I] }], error: "Invalid ARN: Missing account id", [ct]: f }, { [cv]: co, [cu]: [{ [cv]: cp, [cu]: [{ [cv]: bC, endpoint: { [cA]: M, [cB]: bc, [cH]: al }, [ct]: n }, { [cv]: cq, endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.s3-object-lambda-fips.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bc, [cH]: al }, [ct]: n }, { endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.s3-object-lambda.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bc, [cH]: al }, [ct]: n }], [ct]: o }, bd], [ct]: o }, be], [ct]: o }, bf], [ct]: o }, bg], [ct]: o }], [ct]: o }], [ct]: o }, bh], [ct]: o }, { error: "Invalid ARN: bucket ARN is missing a region", [ct]: f }], [ct]: o }, bi], [ct]: o }, { error: "Invalid ARN: Object Lambda ARNs only support `accesspoint` arn types, but found: `{arnType}`", [ct]: f }], [ct]: o }, { [cv]: ce, [cu]: [{ [cv]: cf, [cu]: [{ [cv]: ci, [cu]: [{ [cv]: ce, [cu]: [{ [cv]: ci, [cu]: [aY, { [cv]: cj, [cu]: [aZ, { [cv]: cl, [cu]: [{ [cv]: bG, [cu]: [{ [cv]: [{ [cw]: h, [cx]: [ba, "{partitionResult#name}"] }], [cu]: [{ [cv]: cn, [cu]: [{ [cv]: [{ [cw]: h, [cx]: [aU, B] }], [cu]: [{ [cv]: co, [cu]: [{ [cv]: cp, [cu]: [{ [cv]: bB, error: "Access Points do not support S3 Accelerate", [ct]: f }, { [cv]: bH, endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.s3-accesspoint-fips.dualstack.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bj, [cH]: al }, [ct]: n }, { [cv]: bI, endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.s3-accesspoint-fips.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bj, [cH]: al }, [ct]: n }, { [cv]: bJ, endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.s3-accesspoint.dualstack.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bj, [cH]: al }, [ct]: n }, { [cv]: [as, ar, Z, ag], endpoint: { [cA]: M, [cB]: bj, [cH]: al }, [ct]: n }, { [cv]: bK, endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.s3-accesspoint.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bj, [cH]: al }, [ct]: n }], [ct]: o }, bd], [ct]: o }, be], [ct]: o }, { error: "Invalid ARN: The ARN was not for the S3 service, found: {bucketArn#service}", [ct]: f }], [ct]: o }, bf], [ct]: o }, bg], [ct]: o }], [ct]: o }], [ct]: o }, bh], [ct]: o }], [ct]: o }], [ct]: o }, { [cv]: [{ [cw]: y, [cx]: [aV, c] }], [cu]: [{ [cv]: ch, error: "S3 MRAP does not support dual-stack", [ct]: f }, { [cv]: cq, error: "S3 MRAP does not support FIPS", [ct]: f }, { [cv]: bB, error: "S3 MRAP does not support S3 Accelerate", [ct]: f }, { [cv]: [{ [cw]: e, [cx]: [{ [cy]: "DisableMultiRegionAccessPoints" }, c] }], error: "Invalid configuration: Multi-Region Access Point ARNs are disabled.", [ct]: f }, { [cv]: [{ [cw]: g, [cx]: by, [cz]: N }], [cu]: [{ [cv]: [{ [cw]: h, [cx]: [{ [cw]: i, [cx]: [{ [cy]: N }, j] }, { [cw]: i, [cx]: [aS, "partition"] }] }], [cu]: [{ endpoint: { [cA]: "https://{accessPointName}.accesspoint.s3-global.{mrapPartition#dnsSuffix}", [cB]: { [cD]: [{ [cE]: c, name: z, [cF]: B, [cI]: cb }] }, [cH]: al }, [ct]: n }], [ct]: o }, { error: "Client was configured for partition `{mrapPartition#name}` but bucket referred to partition `{bucketArn#partition}`", [ct]: f }], [ct]: o }], [ct]: o }, { error: "Invalid Access Point Name", [ct]: f }], [ct]: o }, bi], [ct]: o }, { [cv]: [{ [cw]: h, [cx]: [aU, A] }], [cu]: [{ [cv]: ch, error: "S3 Outposts does not support Dual-stack", [ct]: f }, { [cv]: cq, error: "S3 Outposts does not support FIPS", [ct]: f }, { [cv]: bB, error: "S3 Outposts does not support S3 Accelerate", [ct]: f }, { [cv]: [{ [cw]: d, [cx]: [{ [cw]: i, [cx]: [aS, "resourceId[4]"] }] }], error: "Invalid Arn: Outpost Access Point ARN contains sub resources", [ct]: f }, { [cv]: [{ [cw]: i, [cx]: cg, [cz]: x }], [cu]: [{ [cv]: bZ, [cu]: [aZ, { [cv]: cl, [cu]: [{ [cv]: bG, [cu]: [{ [cv]: cm, [cu]: [{ [cv]: cn, [cu]: [{ [cv]: co, [cu]: [{ [cv]: [{ [cw]: i, [cx]: ck, [cz]: O }], [cu]: [{ [cv]: [{ [cw]: i, [cx]: [aS, "resourceId[3]"], [cz]: L }], [cu]: [{ [cv]: [{ [cw]: h, [cx]: [{ [cy]: O }, K] }], [cu]: [{ [cv]: bC, endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.{outpostId}.{url#authority}", [cB]: bk, [cH]: al }, [ct]: n }, { endpoint: { [cA]: "https://{accessPointName}-{bucketArn#accountId}.{outpostId}.s3-outposts.{bucketArn#region}.{bucketPartition#dnsSuffix}", [cB]: bk, [cH]: al }, [ct]: n }], [ct]: o }, { error: "Expected an outpost type `accesspoint`, found {outpostType}", [ct]: f }], [ct]: o }, { error: "Invalid ARN: expected an access point name", [ct]: f }], [ct]: o }, { error: "Invalid ARN: Expected a 4-component resource", [ct]: f }], [ct]: o }, be], [ct]: o }, bf], [ct]: o }, bg], [ct]: o }], [ct]: o }], [ct]: o }, { error: "Invalid ARN: The outpost Id may only contain a-z, A-Z, 0-9 and `-`. Found: `{outpostId}`", [ct]: f }], [ct]: o }, { error: "Invalid ARN: The Outpost Id was not set", [ct]: f }], [ct]: o }, { error: "Invalid ARN: Unrecognized format: {Bucket} (type: {arnType})", [ct]: f }], [ct]: o }, { error: "Invalid ARN: No ARN type specified", [ct]: f }], [ct]: o }, { [cv]: [{ [cw]: k, [cx]: [ad, 0, 4, b], [cz]: P }, { [cw]: h, [cx]: [{ [cy]: P }, "arn:"] }, { [cw]: r, [cx]: [{ [cw]: d, [cx]: [bl] }] }], error: "Invalid ARN: `{Bucket}` was not a valid ARN", [ct]: f }, { [cv]: [{ [cw]: e, [cx]: [az, c] }, bl], error: "Path-style addressing cannot be used with ARN buckets", [ct]: f }, { [cv]: bE, [cu]: [{ [cv]: bG, [cu]: [{ [cv]: [aA], [cu]: [{ [cv]: [Y, aq, X, aB], endpoint: { [cA]: "https://s3-fips.dualstack.us-east-1.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [Y, aq, X, aD, aE], [cu]: [{ endpoint: bm, [ct]: n }], [ct]: o }, { [cv]: [Y, aq, X, aD, aH], endpoint: bm, [ct]: n }, { [cv]: [ar, aq, X, aB], endpoint: { [cA]: "https://s3-fips.us-east-1.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, aq, X, aD, aE], [cu]: [{ endpoint: bn, [ct]: n }], [ct]: o }, { [cv]: [ar, aq, X, aD, aH], endpoint: bn, [ct]: n }, { [cv]: [Y, aq, as, aB], endpoint: { [cA]: "https://s3.dualstack.us-east-1.{partitionResult#dnsSuffix}/{uri_encoded_bucket}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [Y, aq, as, aD, aE], [cu]: [{ endpoint: bo, [ct]: n }], [ct]: o }, { [cv]: [Y, aq, as, aD, aH], endpoint: bo, [ct]: n }, { [cv]: [ar, Z, ag, as, aB], endpoint: { [cA]: Q, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, Z, ag, as, aD, aE], [cu]: [{ [cv]: cd, endpoint: bp, [ct]: n }, { endpoint: bp, [ct]: n }], [ct]: o }, { [cv]: [ar, Z, ag, as, aD, aH], endpoint: bp, [ct]: n }, { [cv]: [ar, aq, as, aB], endpoint: { [cA]: R, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [ar, aq, as, aD, aE], [cu]: [{ [cv]: cd, endpoint: { [cA]: R, [cB]: aG, [cH]: al }, [ct]: n }, { endpoint: bq, [ct]: n }], [ct]: o }, { [cv]: [ar, aq, as, aD, aH], endpoint: bq, [ct]: n }], [ct]: o }, { error: "Path-style addressing cannot be used with S3 Accelerate", [ct]: f }], [ct]: o }], [ct]: o }], [ct]: o }, { [cv]: [{ [cw]: d, [cx]: [br] }, { [cw]: e, [cx]: [br, c] }], [cu]: [{ [cv]: bG, [cu]: [{ [cv]: cr, [cu]: [aW, aX, { [cv]: bC, endpoint: { [cA]: t, [cB]: bs, [cH]: al }, [ct]: n }, { [cv]: cq, endpoint: { [cA]: "https://s3-object-lambda-fips.{Region}.{partitionResult#dnsSuffix}", [cB]: bs, [cH]: al }, [ct]: n }, { endpoint: { [cA]: "https://s3-object-lambda.{Region}.{partitionResult#dnsSuffix}", [cB]: bs, [cH]: al }, [ct]: n }], [ct]: o }, aR], [ct]: o }], [ct]: o }, { [cv]: [au], [cu]: [{ [cv]: bG, [cu]: [{ [cv]: cr, [cu]: [{ [cv]: [X, Y, aq, aB], endpoint: { [cA]: "https://s3-fips.dualstack.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [X, Y, aq, aD, aE], [cu]: [{ endpoint: bt, [ct]: n }], [ct]: o }, { [cv]: [X, Y, aq, aD, aH], endpoint: bt, [ct]: n }, { [cv]: [X, ar, aq, aB], endpoint: { [cA]: "https://s3-fips.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [X, ar, aq, aD, aE], [cu]: [{ endpoint: bu, [ct]: n }], [ct]: o }, { [cv]: [X, ar, aq, aD, aH], endpoint: bu, [ct]: n }, { [cv]: [as, Y, aq, aB], endpoint: { [cA]: "https://s3.dualstack.us-east-1.{partitionResult#dnsSuffix}", [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [as, Y, aq, aD, aE], [cu]: [{ endpoint: bv, [ct]: n }], [ct]: o }, { [cv]: [as, Y, aq, aD, aH], endpoint: bv, [ct]: n }, { [cv]: [as, ar, Z, ag, aB], endpoint: { [cA]: t, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [as, ar, Z, ag, aD, aE], [cu]: [{ [cv]: cd, endpoint: bw, [ct]: n }, { endpoint: bw, [ct]: n }], [ct]: o }, { [cv]: [as, ar, Z, ag, aD, aH], endpoint: bw, [ct]: n }, { [cv]: [as, ar, aq, aB], endpoint: { [cA]: S, [cB]: aC, [cH]: al }, [ct]: n }, { [cv]: [as, ar, aq, aD, aE], [cu]: [{ [cv]: cd, endpoint: { [cA]: S, [cB]: aG, [cH]: al }, [ct]: n }, { endpoint: bx, [ct]: n }], [ct]: o }, { [cv]: [as, ar, aq, aD, aH], endpoint: bx, [ct]: n }], [ct]: o }, aR], [ct]: o }], [ct]: o }], [ct]: o }, { error: "A region must be set when sending requests to S3.", [ct]: f }] };
var ruleSet = _data;

// node_modules/@aws-sdk/client-s3/dist-es/endpoint/endpointResolver.js
var cache = new EndpointCache({
  size: 50,
  params: [
    "Accelerate",
    "Bucket",
    "DisableAccessPoints",
    "DisableMultiRegionAccessPoints",
    "DisableS3ExpressSessionAuth",
    "Endpoint",
    "ForcePathStyle",
    "Region",
    "UseArnRegion",
    "UseDualStack",
    "UseFIPS",
    "UseGlobalEndpoint",
    "UseObjectLambdaEndpoint",
    "UseS3ExpressControlEndpoint"
  ]
});
var defaultEndpointResolver = (endpointParams, context = {}) => {
  return cache.get(endpointParams, () => resolveEndpoint(ruleSet, {
    endpointParams,
    logger: context.logger
  }));
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@aws-sdk/client-s3/dist-es/auth/httpAuthSchemeProvider.js
var createEndpointRuleSetHttpAuthSchemeParametersProvider = (defaultHttpAuthSchemeParametersProvider) => async (config, context, input) => {
  if (!input) {
    throw new Error(`Could not find \`input\` for \`defaultEndpointRuleSetHttpAuthSchemeParametersProvider\``);
  }
  const defaultParameters = await defaultHttpAuthSchemeParametersProvider(config, context, input);
  const instructionsFn = getSmithyContext(context)?.commandInstance?.constructor?.getEndpointParameterInstructions;
  if (!instructionsFn) {
    throw new Error(`getEndpointParameterInstructions() is not defined on \`${context.commandName}\``);
  }
  const endpointParameters = await resolveParams(input, { getEndpointParameterInstructions: instructionsFn }, config);
  return Object.assign(defaultParameters, endpointParameters);
};
var _defaultS3HttpAuthSchemeParametersProvider = async (config, context, input) => {
  return {
    operation: getSmithyContext(context).operation,
    region: await normalizeProvider(config.region)() || (() => {
      throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
    })()
  };
};
var defaultS3HttpAuthSchemeParametersProvider = createEndpointRuleSetHttpAuthSchemeParametersProvider(_defaultS3HttpAuthSchemeParametersProvider);
function createAwsAuthSigv4HttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "s3",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createAwsAuthSigv4aHttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4a",
    signingProperties: {
      name: "s3",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
var createEndpointRuleSetHttpAuthSchemeProvider = (defaultEndpointResolver2, defaultHttpAuthSchemeResolver, createHttpAuthOptionFunctions) => {
  const endpointRuleSetHttpAuthSchemeProvider = (authParameters) => {
    const endpoint = defaultEndpointResolver2(authParameters);
    const authSchemes = endpoint.properties?.authSchemes;
    if (!authSchemes) {
      return defaultHttpAuthSchemeResolver(authParameters);
    }
    const options = [];
    for (const scheme of authSchemes) {
      const { name: resolvedName, properties = {}, ...rest } = scheme;
      const name = resolvedName.toLowerCase();
      if (resolvedName !== name) {
        console.warn(`HttpAuthScheme has been normalized with lowercasing: \`${resolvedName}\` to \`${name}\``);
      }
      let schemeId;
      if (name === "sigv4a") {
        schemeId = "aws.auth#sigv4a";
        const sigv4Present = authSchemes.find((s2) => {
          const name2 = s2.name.toLowerCase();
          return name2 !== "sigv4a" && name2.startsWith("sigv4");
        });
        if (SignatureV4MultiRegion.sigv4aDependency() === "none" && sigv4Present) {
          continue;
        }
      } else if (name.startsWith("sigv4")) {
        schemeId = "aws.auth#sigv4";
      } else {
        throw new Error(`Unknown HttpAuthScheme found in \`@smithy.rules#endpointRuleSet\`: \`${name}\``);
      }
      const createOption = createHttpAuthOptionFunctions[schemeId];
      if (!createOption) {
        throw new Error(`Could not find HttpAuthOption create function for \`${schemeId}\``);
      }
      const option = createOption(authParameters);
      option.schemeId = schemeId;
      option.signingProperties = { ...option.signingProperties || {}, ...rest, ...properties };
      options.push(option);
    }
    return options;
  };
  return endpointRuleSetHttpAuthSchemeProvider;
};
var _defaultS3HttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    default: {
      options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
      options.push(createAwsAuthSigv4aHttpAuthOption(authParameters));
    }
  }
  return options;
};
var defaultS3HttpAuthSchemeProvider = createEndpointRuleSetHttpAuthSchemeProvider(defaultEndpointResolver, _defaultS3HttpAuthSchemeProvider, {
  "aws.auth#sigv4": createAwsAuthSigv4HttpAuthOption,
  "aws.auth#sigv4a": createAwsAuthSigv4aHttpAuthOption
});
var resolveHttpAuthSchemeConfig = (config) => {
  const config_0 = resolveAwsSdkSigV4Config(config);
  const config_1 = resolveAwsSdkSigV4AConfig(config_0);
  return Object.assign(config_1, {
    authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
  });
};

// node_modules/@aws-sdk/client-s3/dist-es/endpoint/EndpointParameters.js
var resolveClientEndpointParameters = (options) => {
  return Object.assign(options, {
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    forcePathStyle: options.forcePathStyle ?? false,
    useAccelerateEndpoint: options.useAccelerateEndpoint ?? false,
    useGlobalEndpoint: options.useGlobalEndpoint ?? false,
    disableMultiregionAccessPoints: options.disableMultiregionAccessPoints ?? false,
    defaultSigningName: "s3"
  });
};
var commonParams = {
  ForcePathStyle: { type: "clientContextParams", name: "forcePathStyle" },
  UseArnRegion: { type: "clientContextParams", name: "useArnRegion" },
  DisableMultiRegionAccessPoints: { type: "clientContextParams", name: "disableMultiregionAccessPoints" },
  Accelerate: { type: "clientContextParams", name: "useAccelerateEndpoint" },
  DisableS3ExpressSessionAuth: { type: "clientContextParams", name: "disableS3ExpressSessionAuth" },
  UseGlobalEndpoint: { type: "builtInParams", name: "useGlobalEndpoint" },
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// node_modules/@aws-sdk/client-s3/dist-es/models/S3ServiceException.js
var S3ServiceException = class _S3ServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _S3ServiceException.prototype);
  }
};

// node_modules/@aws-sdk/client-s3/dist-es/models/models_0.js
var NoSuchUpload = class _NoSuchUpload extends S3ServiceException {
  name = "NoSuchUpload";
  $fault = "client";
  constructor(opts) {
    super({
      name: "NoSuchUpload",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _NoSuchUpload.prototype);
  }
};
var ObjectNotInActiveTierError = class _ObjectNotInActiveTierError extends S3ServiceException {
  name = "ObjectNotInActiveTierError";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ObjectNotInActiveTierError",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ObjectNotInActiveTierError.prototype);
  }
};
var BucketAlreadyExists = class _BucketAlreadyExists extends S3ServiceException {
  name = "BucketAlreadyExists";
  $fault = "client";
  constructor(opts) {
    super({
      name: "BucketAlreadyExists",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _BucketAlreadyExists.prototype);
  }
};
var BucketAlreadyOwnedByYou = class _BucketAlreadyOwnedByYou extends S3ServiceException {
  name = "BucketAlreadyOwnedByYou";
  $fault = "client";
  constructor(opts) {
    super({
      name: "BucketAlreadyOwnedByYou",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _BucketAlreadyOwnedByYou.prototype);
  }
};
var NoSuchBucket = class _NoSuchBucket extends S3ServiceException {
  name = "NoSuchBucket";
  $fault = "client";
  constructor(opts) {
    super({
      name: "NoSuchBucket",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _NoSuchBucket.prototype);
  }
};
var AnalyticsFilter;
(function(AnalyticsFilter2) {
  AnalyticsFilter2.visit = (value, visitor) => {
    if (value.Prefix !== void 0)
      return visitor.Prefix(value.Prefix);
    if (value.Tag !== void 0)
      return visitor.Tag(value.Tag);
    if (value.And !== void 0)
      return visitor.And(value.And);
    return visitor._(value.$unknown[0], value.$unknown[1]);
  };
})(AnalyticsFilter || (AnalyticsFilter = {}));
var MetricsFilter;
(function(MetricsFilter2) {
  MetricsFilter2.visit = (value, visitor) => {
    if (value.Prefix !== void 0)
      return visitor.Prefix(value.Prefix);
    if (value.Tag !== void 0)
      return visitor.Tag(value.Tag);
    if (value.AccessPointArn !== void 0)
      return visitor.AccessPointArn(value.AccessPointArn);
    if (value.And !== void 0)
      return visitor.And(value.And);
    return visitor._(value.$unknown[0], value.$unknown[1]);
  };
})(MetricsFilter || (MetricsFilter = {}));
var InvalidObjectState = class _InvalidObjectState extends S3ServiceException {
  name = "InvalidObjectState";
  $fault = "client";
  StorageClass;
  AccessTier;
  constructor(opts) {
    super({
      name: "InvalidObjectState",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidObjectState.prototype);
    this.StorageClass = opts.StorageClass;
    this.AccessTier = opts.AccessTier;
  }
};
var NoSuchKey = class _NoSuchKey extends S3ServiceException {
  name = "NoSuchKey";
  $fault = "client";
  constructor(opts) {
    super({
      name: "NoSuchKey",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _NoSuchKey.prototype);
  }
};
var NotFound = class _NotFound extends S3ServiceException {
  name = "NotFound";
  $fault = "client";
  constructor(opts) {
    super({
      name: "NotFound",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _NotFound.prototype);
  }
};
var SessionCredentialsFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.SecretAccessKey && { SecretAccessKey: SENSITIVE_STRING2 },
  ...obj.SessionToken && { SessionToken: SENSITIVE_STRING2 }
});
var CreateSessionOutputFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.SSEKMSKeyId && { SSEKMSKeyId: SENSITIVE_STRING2 },
  ...obj.SSEKMSEncryptionContext && { SSEKMSEncryptionContext: SENSITIVE_STRING2 },
  ...obj.Credentials && { Credentials: SessionCredentialsFilterSensitiveLog(obj.Credentials) }
});
var CreateSessionRequestFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.SSEKMSKeyId && { SSEKMSKeyId: SENSITIVE_STRING2 },
  ...obj.SSEKMSEncryptionContext && { SSEKMSEncryptionContext: SENSITIVE_STRING2 }
});

// node_modules/@aws-sdk/client-s3/dist-es/models/models_1.js
var EncryptionTypeMismatch = class _EncryptionTypeMismatch extends S3ServiceException {
  name = "EncryptionTypeMismatch";
  $fault = "client";
  constructor(opts) {
    super({
      name: "EncryptionTypeMismatch",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _EncryptionTypeMismatch.prototype);
  }
};
var InvalidRequest = class _InvalidRequest extends S3ServiceException {
  name = "InvalidRequest";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidRequest",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidRequest.prototype);
  }
};
var InvalidWriteOffset = class _InvalidWriteOffset extends S3ServiceException {
  name = "InvalidWriteOffset";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidWriteOffset",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidWriteOffset.prototype);
  }
};
var TooManyParts = class _TooManyParts extends S3ServiceException {
  name = "TooManyParts";
  $fault = "client";
  constructor(opts) {
    super({
      name: "TooManyParts",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TooManyParts.prototype);
  }
};
var IdempotencyParameterMismatch = class _IdempotencyParameterMismatch extends S3ServiceException {
  name = "IdempotencyParameterMismatch";
  $fault = "client";
  constructor(opts) {
    super({
      name: "IdempotencyParameterMismatch",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _IdempotencyParameterMismatch.prototype);
  }
};
var ObjectAlreadyInActiveTierError = class _ObjectAlreadyInActiveTierError extends S3ServiceException {
  name = "ObjectAlreadyInActiveTierError";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ObjectAlreadyInActiveTierError",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ObjectAlreadyInActiveTierError.prototype);
  }
};
var SelectObjectContentEventStream;
(function(SelectObjectContentEventStream2) {
  SelectObjectContentEventStream2.visit = (value, visitor) => {
    if (value.Records !== void 0)
      return visitor.Records(value.Records);
    if (value.Stats !== void 0)
      return visitor.Stats(value.Stats);
    if (value.Progress !== void 0)
      return visitor.Progress(value.Progress);
    if (value.Cont !== void 0)
      return visitor.Cont(value.Cont);
    if (value.End !== void 0)
      return visitor.End(value.End);
    return visitor._(value.$unknown[0], value.$unknown[1]);
  };
})(SelectObjectContentEventStream || (SelectObjectContentEventStream = {}));
var PutObjectOutputFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.SSEKMSKeyId && { SSEKMSKeyId: SENSITIVE_STRING2 },
  ...obj.SSEKMSEncryptionContext && { SSEKMSEncryptionContext: SENSITIVE_STRING2 }
});
var PutObjectRequestFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.SSECustomerKey && { SSECustomerKey: SENSITIVE_STRING2 },
  ...obj.SSEKMSKeyId && { SSEKMSKeyId: SENSITIVE_STRING2 },
  ...obj.SSEKMSEncryptionContext && { SSEKMSEncryptionContext: SENSITIVE_STRING2 }
});

// node_modules/@aws-sdk/client-s3/dist-es/protocols/Aws_restXml.js
var se_CreateSessionCommand = async (input, context) => {
  const b2 = requestBuilder(input, context);
  const headers = map({}, isSerializableHeaderValue, {
    [_xacsm]: input[_SM],
    [_xasse]: input[_SSE],
    [_xasseakki]: input[_SSEKMSKI],
    [_xassec]: input[_SSEKMSEC],
    [_xassebke]: [() => isSerializableHeaderValue(input[_BKE]), () => input[_BKE].toString()]
  });
  b2.bp("/");
  b2.p("Bucket", () => input.Bucket, "{Bucket}", false);
  const query = map({
    [_s]: [, ""]
  });
  let body;
  b2.m("GET").h(headers).q(query).b(body);
  return b2.build();
};
var se_PutObjectCommand = async (input, context) => {
  const b2 = requestBuilder(input, context);
  const headers = map({}, isSerializableHeaderValue, {
    ...input.Metadata !== void 0 && Object.keys(input.Metadata).reduce((acc, suffix) => {
      acc[`x-amz-meta-${suffix.toLowerCase()}`] = input.Metadata[suffix];
      return acc;
    }, {}),
    [_ct]: input[_CTo] || "application/octet-stream",
    [_xaa]: input[_ACL],
    [_cc]: input[_CC],
    [_cd]: input[_CD],
    [_ce]: input[_CE],
    [_cl]: input[_CL],
    [_cl_]: [() => isSerializableHeaderValue(input[_CLo]), () => input[_CLo].toString()],
    [_cm]: input[_CMD],
    [_xasca]: input[_CA],
    [_xacc]: input[_CCRC],
    [_xacc_]: input[_CCRCC],
    [_xacc__]: input[_CCRCNVME],
    [_xacs]: input[_CSHA],
    [_xacs_]: input[_CSHAh],
    [_e]: [() => isSerializableHeaderValue(input[_E]), () => dateToUtcString(input[_E]).toString()],
    [_im]: input[_IM],
    [_inm]: input[_INM],
    [_xagfc]: input[_GFC],
    [_xagr]: input[_GR],
    [_xagra]: input[_GRACP],
    [_xagwa]: input[_GWACP],
    [_xawob]: [() => isSerializableHeaderValue(input[_WOB]), () => input[_WOB].toString()],
    [_xasse]: input[_SSE],
    [_xasc]: input[_SC],
    [_xawrl]: input[_WRL],
    [_xasseca]: input[_SSECA],
    [_xasseck]: input[_SSECK],
    [_xasseckm]: input[_SSECKMD],
    [_xasseakki]: input[_SSEKMSKI],
    [_xassec]: input[_SSEKMSEC],
    [_xassebke]: [() => isSerializableHeaderValue(input[_BKE]), () => input[_BKE].toString()],
    [_xarp]: input[_RP],
    [_xat]: input[_T],
    [_xaolm]: input[_OLM],
    [_xaolrud]: [() => isSerializableHeaderValue(input[_OLRUD]), () => serializeDateTime(input[_OLRUD]).toString()],
    [_xaollh]: input[_OLLHS],
    [_xaebo]: input[_EBO]
  });
  b2.bp("/{Key+}");
  b2.p("Bucket", () => input.Bucket, "{Bucket}", false);
  b2.p("Key", () => input.Key, "{Key+}", true);
  const query = map({
    [_xi]: [, "PutObject"]
  });
  let body;
  let contents;
  if (input.Body !== void 0) {
    contents = input.Body;
    body = contents;
  }
  b2.m("PUT").h(headers).q(query).b(body);
  return b2.build();
};
var de_CreateSessionCommand = async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = map({
    $metadata: deserializeMetadata2(output),
    [_SSE]: [, output.headers[_xasse]],
    [_SSEKMSKI]: [, output.headers[_xasseakki]],
    [_SSEKMSEC]: [, output.headers[_xassec]],
    [_BKE]: [() => void 0 !== output.headers[_xassebke], () => parseBoolean(output.headers[_xassebke])]
  });
  const data = expectNonNull(expectObject(await parseXmlBody(output.body, context)), "body");
  if (data[_C] != null) {
    contents[_C] = de_SessionCredentials(data[_C], context);
  }
  return contents;
};
var de_PutObjectCommand = async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = map({
    $metadata: deserializeMetadata2(output),
    [_Exp]: [, output.headers[_xae]],
    [_ETa]: [, output.headers[_eta]],
    [_CCRC]: [, output.headers[_xacc]],
    [_CCRCC]: [, output.headers[_xacc_]],
    [_CCRCNVME]: [, output.headers[_xacc__]],
    [_CSHA]: [, output.headers[_xacs]],
    [_CSHAh]: [, output.headers[_xacs_]],
    [_CT]: [, output.headers[_xact]],
    [_SSE]: [, output.headers[_xasse]],
    [_VI]: [, output.headers[_xavi]],
    [_SSECA]: [, output.headers[_xasseca]],
    [_SSECKMD]: [, output.headers[_xasseckm]],
    [_SSEKMSKI]: [, output.headers[_xasseakki]],
    [_SSEKMSEC]: [, output.headers[_xassec]],
    [_BKE]: [() => void 0 !== output.headers[_xassebke], () => parseBoolean(output.headers[_xassebke])],
    [_Si]: [() => void 0 !== output.headers[_xaos], () => strictParseLong(output.headers[_xaos])],
    [_RC]: [, output.headers[_xarc]]
  });
  await collectBody(output.body, context);
  return contents;
};
var de_CommandError = async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await parseXmlErrorBody(output.body, context)
  };
  const errorCode = loadRestXmlErrorCode(output, parsedOutput.body);
  switch (errorCode) {
    case "NoSuchUpload":
    case "com.amazonaws.s3#NoSuchUpload":
      throw await de_NoSuchUploadRes(parsedOutput, context);
    case "ObjectNotInActiveTierError":
    case "com.amazonaws.s3#ObjectNotInActiveTierError":
      throw await de_ObjectNotInActiveTierErrorRes(parsedOutput, context);
    case "BucketAlreadyExists":
    case "com.amazonaws.s3#BucketAlreadyExists":
      throw await de_BucketAlreadyExistsRes(parsedOutput, context);
    case "BucketAlreadyOwnedByYou":
    case "com.amazonaws.s3#BucketAlreadyOwnedByYou":
      throw await de_BucketAlreadyOwnedByYouRes(parsedOutput, context);
    case "NoSuchBucket":
    case "com.amazonaws.s3#NoSuchBucket":
      throw await de_NoSuchBucketRes(parsedOutput, context);
    case "InvalidObjectState":
    case "com.amazonaws.s3#InvalidObjectState":
      throw await de_InvalidObjectStateRes(parsedOutput, context);
    case "NoSuchKey":
    case "com.amazonaws.s3#NoSuchKey":
      throw await de_NoSuchKeyRes(parsedOutput, context);
    case "NotFound":
    case "com.amazonaws.s3#NotFound":
      throw await de_NotFoundRes(parsedOutput, context);
    case "EncryptionTypeMismatch":
    case "com.amazonaws.s3#EncryptionTypeMismatch":
      throw await de_EncryptionTypeMismatchRes(parsedOutput, context);
    case "InvalidRequest":
    case "com.amazonaws.s3#InvalidRequest":
      throw await de_InvalidRequestRes(parsedOutput, context);
    case "InvalidWriteOffset":
    case "com.amazonaws.s3#InvalidWriteOffset":
      throw await de_InvalidWriteOffsetRes(parsedOutput, context);
    case "TooManyParts":
    case "com.amazonaws.s3#TooManyParts":
      throw await de_TooManyPartsRes(parsedOutput, context);
    case "IdempotencyParameterMismatch":
    case "com.amazonaws.s3#IdempotencyParameterMismatch":
      throw await de_IdempotencyParameterMismatchRes(parsedOutput, context);
    case "ObjectAlreadyInActiveTierError":
    case "com.amazonaws.s3#ObjectAlreadyInActiveTierError":
      throw await de_ObjectAlreadyInActiveTierErrorRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError2({
        output,
        parsedBody,
        errorCode
      });
  }
};
var throwDefaultError2 = withBaseException(S3ServiceException);
var de_BucketAlreadyExistsRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new BucketAlreadyExists({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_BucketAlreadyOwnedByYouRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new BucketAlreadyOwnedByYou({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_EncryptionTypeMismatchRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new EncryptionTypeMismatch({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_IdempotencyParameterMismatchRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new IdempotencyParameterMismatch({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidObjectStateRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  if (data[_AT] != null) {
    contents[_AT] = expectString(data[_AT]);
  }
  if (data[_SC] != null) {
    contents[_SC] = expectString(data[_SC]);
  }
  const exception = new InvalidObjectState({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidRequestRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new InvalidRequest({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidWriteOffsetRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new InvalidWriteOffset({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_NoSuchBucketRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new NoSuchBucket({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_NoSuchKeyRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new NoSuchKey({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_NoSuchUploadRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new NoSuchUpload({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_NotFoundRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new NotFound({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_ObjectAlreadyInActiveTierErrorRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new ObjectAlreadyInActiveTierError({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_ObjectNotInActiveTierErrorRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new ObjectNotInActiveTierError({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_TooManyPartsRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const exception = new TooManyParts({
    $metadata: deserializeMetadata2(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_SessionCredentials = (output, context) => {
  const contents = {};
  if (output[_AKI] != null) {
    contents[_AKI] = expectString(output[_AKI]);
  }
  if (output[_SAK] != null) {
    contents[_SAK] = expectString(output[_SAK]);
  }
  if (output[_ST] != null) {
    contents[_ST] = expectString(output[_ST]);
  }
  if (output[_Exp] != null) {
    contents[_Exp] = expectNonNull(parseRfc3339DateTimeWithOffset(output[_Exp]));
  }
  return contents;
};
var deserializeMetadata2 = (output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
});
var _ACL = "ACL";
var _AKI = "AccessKeyId";
var _AT = "AccessTier";
var _BKE = "BucketKeyEnabled";
var _C = "Credentials";
var _CA = "ChecksumAlgorithm";
var _CC = "CacheControl";
var _CCRC = "ChecksumCRC32";
var _CCRCC = "ChecksumCRC32C";
var _CCRCNVME = "ChecksumCRC64NVME";
var _CD = "ContentDisposition";
var _CE = "ContentEncoding";
var _CL = "ContentLanguage";
var _CLo = "ContentLength";
var _CMD = "ContentMD5";
var _CSHA = "ChecksumSHA1";
var _CSHAh = "ChecksumSHA256";
var _CT = "ChecksumType";
var _CTo = "ContentType";
var _E = "Expires";
var _EBO = "ExpectedBucketOwner";
var _ETa = "ETag";
var _Exp = "Expiration";
var _GFC = "GrantFullControl";
var _GR = "GrantRead";
var _GRACP = "GrantReadACP";
var _GWACP = "GrantWriteACP";
var _IM = "IfMatch";
var _INM = "IfNoneMatch";
var _OLLHS = "ObjectLockLegalHoldStatus";
var _OLM = "ObjectLockMode";
var _OLRUD = "ObjectLockRetainUntilDate";
var _RC = "RequestCharged";
var _RP = "RequestPayer";
var _SAK = "SecretAccessKey";
var _SC = "StorageClass";
var _SM = "SessionMode";
var _SSE = "ServerSideEncryption";
var _SSECA = "SSECustomerAlgorithm";
var _SSECK = "SSECustomerKey";
var _SSECKMD = "SSECustomerKeyMD5";
var _SSEKMSEC = "SSEKMSEncryptionContext";
var _SSEKMSKI = "SSEKMSKeyId";
var _ST = "SessionToken";
var _Si = "Size";
var _T = "Tagging";
var _VI = "VersionId";
var _WOB = "WriteOffsetBytes";
var _WRL = "WebsiteRedirectLocation";
var _cc = "cache-control";
var _cd = "content-disposition";
var _ce = "content-encoding";
var _cl = "content-language";
var _cl_ = "content-length";
var _cm = "content-md5";
var _ct = "content-type";
var _e = "expires";
var _eta = "etag";
var _im = "if-match";
var _inm = "if-none-match";
var _s = "session";
var _xaa = "x-amz-acl";
var _xacc = "x-amz-checksum-crc32";
var _xacc_ = "x-amz-checksum-crc32c";
var _xacc__ = "x-amz-checksum-crc64nvme";
var _xacs = "x-amz-checksum-sha1";
var _xacs_ = "x-amz-checksum-sha256";
var _xacsm = "x-amz-create-session-mode";
var _xact = "x-amz-checksum-type";
var _xae = "x-amz-expiration";
var _xaebo = "x-amz-expected-bucket-owner";
var _xagfc = "x-amz-grant-full-control";
var _xagr = "x-amz-grant-read";
var _xagra = "x-amz-grant-read-acp";
var _xagwa = "x-amz-grant-write-acp";
var _xaollh = "x-amz-object-lock-legal-hold";
var _xaolm = "x-amz-object-lock-mode";
var _xaolrud = "x-amz-object-lock-retain-until-date";
var _xaos = "x-amz-object-size";
var _xarc = "x-amz-request-charged";
var _xarp = "x-amz-request-payer";
var _xasc = "x-amz-storage-class";
var _xasca = "x-amz-sdk-checksum-algorithm";
var _xasse = "x-amz-server-side-encryption";
var _xasseakki = "x-amz-server-side-encryption-aws-kms-key-id";
var _xassebke = "x-amz-server-side-encryption-bucket-key-enabled";
var _xassec = "x-amz-server-side-encryption-context";
var _xasseca = "x-amz-server-side-encryption-customer-algorithm";
var _xasseck = "x-amz-server-side-encryption-customer-key";
var _xasseckm = "x-amz-server-side-encryption-customer-key-md5";
var _xat = "x-amz-tagging";
var _xavi = "x-amz-version-id";
var _xawob = "x-amz-write-offset-bytes";
var _xawrl = "x-amz-website-redirect-location";
var _xi = "x-id";

// node_modules/@aws-sdk/client-s3/dist-es/commands/CreateSessionCommand.js
var CreateSessionCommand = class extends Command.classBuilder().ep({
  ...commonParams,
  DisableS3ExpressSessionAuth: { type: "staticContextParams", value: true },
  Bucket: { type: "contextParams", name: "Bucket" }
}).m(function(Command2, cs2, config, o2) {
  return [
    getSerdePlugin(config, this.serialize, this.deserialize),
    getEndpointPlugin(config, Command2.getEndpointParameterInstructions()),
    getThrow200ExceptionsPlugin(config)
  ];
}).s("AmazonS3", "CreateSession", {}).n("S3Client", "CreateSessionCommand").f(CreateSessionRequestFilterSensitiveLog, CreateSessionOutputFilterSensitiveLog).ser(se_CreateSessionCommand).de(de_CreateSessionCommand).build() {
};

// node_modules/@aws-sdk/client-s3/package.json
var package_default = {
  name: "@aws-sdk/client-s3",
  description: "AWS SDK for JavaScript S3 Client for Node.js, Browser and React Native",
  version: "3.927.0",
  scripts: {
    build: "concurrently 'yarn:build:cjs' 'yarn:build:es' 'yarn:build:types'",
    "build:cjs": "node ../../scripts/compilation/inline client-s3",
    "build:es": "tsc -p tsconfig.es.json",
    "build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
    "build:types": "tsc -p tsconfig.types.json",
    "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
    clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
    "extract:docs": "api-extractor run --local",
    "generate:client": "node ../../scripts/generate-clients/single-service --solo s3",
    test: "yarn g:vitest run",
    "test:browser": "node ./test/browser-build/esbuild && yarn g:vitest run -c vitest.config.browser.mts",
    "test:browser:watch": "node ./test/browser-build/esbuild && yarn g:vitest watch -c vitest.config.browser.mts",
    "test:e2e": "yarn g:vitest run -c vitest.config.e2e.mts && yarn test:browser",
    "test:e2e:watch": "yarn g:vitest watch -c vitest.config.e2e.mts",
    "test:integration": "yarn g:vitest run -c vitest.config.integ.mts",
    "test:integration:watch": "yarn g:vitest watch -c vitest.config.integ.mts",
    "test:watch": "yarn g:vitest watch"
  },
  main: "./dist-cjs/index.js",
  types: "./dist-types/index.d.ts",
  module: "./dist-es/index.js",
  sideEffects: false,
  dependencies: {
    "@aws-crypto/sha1-browser": "5.2.0",
    "@aws-crypto/sha256-browser": "5.2.0",
    "@aws-crypto/sha256-js": "5.2.0",
    "@aws-sdk/core": "3.927.0",
    "@aws-sdk/credential-provider-node": "3.927.0",
    "@aws-sdk/middleware-bucket-endpoint": "3.922.0",
    "@aws-sdk/middleware-expect-continue": "3.922.0",
    "@aws-sdk/middleware-flexible-checksums": "3.927.0",
    "@aws-sdk/middleware-host-header": "3.922.0",
    "@aws-sdk/middleware-location-constraint": "3.922.0",
    "@aws-sdk/middleware-logger": "3.922.0",
    "@aws-sdk/middleware-recursion-detection": "3.922.0",
    "@aws-sdk/middleware-sdk-s3": "3.927.0",
    "@aws-sdk/middleware-ssec": "3.922.0",
    "@aws-sdk/middleware-user-agent": "3.927.0",
    "@aws-sdk/region-config-resolver": "3.925.0",
    "@aws-sdk/signature-v4-multi-region": "3.927.0",
    "@aws-sdk/types": "3.922.0",
    "@aws-sdk/util-endpoints": "3.922.0",
    "@aws-sdk/util-user-agent-browser": "3.922.0",
    "@aws-sdk/util-user-agent-node": "3.927.0",
    "@aws-sdk/xml-builder": "3.921.0",
    "@smithy/config-resolver": "^4.4.2",
    "@smithy/core": "^3.17.2",
    "@smithy/eventstream-serde-browser": "^4.2.4",
    "@smithy/eventstream-serde-config-resolver": "^4.3.4",
    "@smithy/eventstream-serde-node": "^4.2.4",
    "@smithy/fetch-http-handler": "^5.3.5",
    "@smithy/hash-blob-browser": "^4.2.5",
    "@smithy/hash-node": "^4.2.4",
    "@smithy/hash-stream-node": "^4.2.4",
    "@smithy/invalid-dependency": "^4.2.4",
    "@smithy/md5-js": "^4.2.4",
    "@smithy/middleware-content-length": "^4.2.4",
    "@smithy/middleware-endpoint": "^4.3.6",
    "@smithy/middleware-retry": "^4.4.6",
    "@smithy/middleware-serde": "^4.2.4",
    "@smithy/middleware-stack": "^4.2.4",
    "@smithy/node-config-provider": "^4.3.4",
    "@smithy/node-http-handler": "^4.4.4",
    "@smithy/protocol-http": "^5.3.4",
    "@smithy/smithy-client": "^4.9.2",
    "@smithy/types": "^4.8.1",
    "@smithy/url-parser": "^4.2.4",
    "@smithy/util-base64": "^4.3.0",
    "@smithy/util-body-length-browser": "^4.2.0",
    "@smithy/util-body-length-node": "^4.2.1",
    "@smithy/util-defaults-mode-browser": "^4.3.5",
    "@smithy/util-defaults-mode-node": "^4.2.8",
    "@smithy/util-endpoints": "^3.2.4",
    "@smithy/util-middleware": "^4.2.4",
    "@smithy/util-retry": "^4.2.4",
    "@smithy/util-stream": "^4.5.5",
    "@smithy/util-utf8": "^4.2.0",
    "@smithy/util-waiter": "^4.2.4",
    "@smithy/uuid": "^1.1.0",
    tslib: "^2.6.2"
  },
  devDependencies: {
    "@aws-sdk/signature-v4-crt": "3.927.0",
    "@tsconfig/node18": "18.2.4",
    "@types/node": "^18.19.69",
    concurrently: "7.0.0",
    "downlevel-dts": "0.10.1",
    rimraf: "3.0.2",
    typescript: "~5.8.3"
  },
  engines: {
    node: ">=18.0.0"
  },
  typesVersions: {
    "<4.0": {
      "dist-types/*": [
        "dist-types/ts3.4/*"
      ]
    }
  },
  files: [
    "dist-*/**"
  ],
  author: {
    name: "AWS SDK for JavaScript Team",
    url: "https://aws.amazon.com/javascript/"
  },
  license: "Apache-2.0",
  browser: {
    "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
  },
  "react-native": {
    "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
  },
  homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-s3",
  repository: {
    type: "git",
    url: "https://github.com/aws/aws-sdk-js-v3.git",
    directory: "clients/client-s3"
  }
};

// node_modules/@aws-crypto/sha1-browser/node_modules/@smithy/util-utf8/dist-es/fromUtf8.browser.js
var fromUtf84 = (input) => new TextEncoder().encode(input);

// node_modules/@aws-crypto/sha1-browser/build/module/isEmptyData.js
function isEmptyData2(data) {
  if (typeof data === "string") {
    return data.length === 0;
  }
  return data.byteLength === 0;
}

// node_modules/@aws-crypto/sha1-browser/build/module/constants.js
var SHA_1_HASH = { name: "SHA-1" };
var SHA_1_HMAC_ALGO = {
  name: "HMAC",
  hash: SHA_1_HASH
};
var EMPTY_DATA_SHA_1 = new Uint8Array([
  218,
  57,
  163,
  238,
  94,
  107,
  75,
  13,
  50,
  85,
  191,
  239,
  149,
  96,
  24,
  144,
  175,
  216,
  7,
  9
]);

// node_modules/@aws-sdk/util-locate-window/dist-es/index.js
var fallbackWindow = {};
function locateWindow() {
  if (typeof window !== "undefined") {
    return window;
  } else if (typeof self !== "undefined") {
    return self;
  }
  return fallbackWindow;
}

// node_modules/@aws-crypto/sha1-browser/build/module/webCryptoSha1.js
var Sha1 = (
  /** @class */
  (function() {
    function Sha13(secret) {
      this.toHash = new Uint8Array(0);
      if (secret !== void 0) {
        this.key = new Promise(function(resolve, reject) {
          locateWindow().crypto.subtle.importKey("raw", convertToBuffer2(secret), SHA_1_HMAC_ALGO, false, ["sign"]).then(resolve, reject);
        });
        this.key.catch(function() {
        });
      }
    }
    Sha13.prototype.update = function(data) {
      if (isEmptyData2(data)) {
        return;
      }
      var update = convertToBuffer2(data);
      var typedArray = new Uint8Array(this.toHash.byteLength + update.byteLength);
      typedArray.set(this.toHash, 0);
      typedArray.set(update, this.toHash.byteLength);
      this.toHash = typedArray;
    };
    Sha13.prototype.digest = function() {
      var _this = this;
      if (this.key) {
        return this.key.then(function(key) {
          return locateWindow().crypto.subtle.sign(SHA_1_HMAC_ALGO, key, _this.toHash).then(function(data) {
            return new Uint8Array(data);
          });
        });
      }
      if (isEmptyData2(this.toHash)) {
        return Promise.resolve(EMPTY_DATA_SHA_1);
      }
      return Promise.resolve().then(function() {
        return locateWindow().crypto.subtle.digest(SHA_1_HASH, _this.toHash);
      }).then(function(data) {
        return Promise.resolve(new Uint8Array(data));
      });
    };
    Sha13.prototype.reset = function() {
      this.toHash = new Uint8Array(0);
    };
    return Sha13;
  })()
);
function convertToBuffer2(data) {
  if (typeof data === "string") {
    return fromUtf84(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
  }
  return new Uint8Array(data);
}

// node_modules/@aws-crypto/supports-web-crypto/build/module/supportsWebCrypto.js
var subtleCryptoMethods = [
  "decrypt",
  "digest",
  "encrypt",
  "exportKey",
  "generateKey",
  "importKey",
  "sign",
  "verify"
];
function supportsWebCrypto(window2) {
  if (supportsSecureRandom(window2) && typeof window2.crypto.subtle === "object") {
    var subtle = window2.crypto.subtle;
    return supportsSubtleCrypto(subtle);
  }
  return false;
}
function supportsSecureRandom(window2) {
  if (typeof window2 === "object" && typeof window2.crypto === "object") {
    var getRandomValues = window2.crypto.getRandomValues;
    return typeof getRandomValues === "function";
  }
  return false;
}
function supportsSubtleCrypto(subtle) {
  return subtle && subtleCryptoMethods.every(function(methodName) {
    return typeof subtle[methodName] === "function";
  });
}

// node_modules/@aws-crypto/sha1-browser/build/module/crossPlatformSha1.js
var Sha12 = (
  /** @class */
  (function() {
    function Sha13(secret) {
      if (supportsWebCrypto(locateWindow())) {
        this.hash = new Sha1(secret);
      } else {
        throw new Error("SHA1 not supported");
      }
    }
    Sha13.prototype.update = function(data, encoding) {
      this.hash.update(convertToBuffer(data));
    };
    Sha13.prototype.digest = function() {
      return this.hash.digest();
    };
    Sha13.prototype.reset = function() {
      this.hash.reset();
    };
    return Sha13;
  })()
);

// node_modules/@aws-crypto/sha256-browser/build/module/constants.js
var SHA_256_HASH = { name: "SHA-256" };
var SHA_256_HMAC_ALGO = {
  name: "HMAC",
  hash: SHA_256_HASH
};
var EMPTY_DATA_SHA_256 = new Uint8Array([
  227,
  176,
  196,
  66,
  152,
  252,
  28,
  20,
  154,
  251,
  244,
  200,
  153,
  111,
  185,
  36,
  39,
  174,
  65,
  228,
  100,
  155,
  147,
  76,
  164,
  149,
  153,
  27,
  120,
  82,
  184,
  85
]);

// node_modules/@aws-crypto/sha256-browser/build/module/webCryptoSha256.js
var Sha256 = (
  /** @class */
  (function() {
    function Sha2564(secret) {
      this.toHash = new Uint8Array(0);
      this.secret = secret;
      this.reset();
    }
    Sha2564.prototype.update = function(data) {
      if (isEmptyData(data)) {
        return;
      }
      var update = convertToBuffer(data);
      var typedArray = new Uint8Array(this.toHash.byteLength + update.byteLength);
      typedArray.set(this.toHash, 0);
      typedArray.set(update, this.toHash.byteLength);
      this.toHash = typedArray;
    };
    Sha2564.prototype.digest = function() {
      var _this = this;
      if (this.key) {
        return this.key.then(function(key) {
          return locateWindow().crypto.subtle.sign(SHA_256_HMAC_ALGO, key, _this.toHash).then(function(data) {
            return new Uint8Array(data);
          });
        });
      }
      if (isEmptyData(this.toHash)) {
        return Promise.resolve(EMPTY_DATA_SHA_256);
      }
      return Promise.resolve().then(function() {
        return locateWindow().crypto.subtle.digest(SHA_256_HASH, _this.toHash);
      }).then(function(data) {
        return Promise.resolve(new Uint8Array(data));
      });
    };
    Sha2564.prototype.reset = function() {
      var _this = this;
      this.toHash = new Uint8Array(0);
      if (this.secret && this.secret !== void 0) {
        this.key = new Promise(function(resolve, reject) {
          locateWindow().crypto.subtle.importKey("raw", convertToBuffer(_this.secret), SHA_256_HMAC_ALGO, false, ["sign"]).then(resolve, reject);
        });
        this.key.catch(function() {
        });
      }
    };
    return Sha2564;
  })()
);

// node_modules/@aws-crypto/sha256-js/build/module/constants.js
var BLOCK_SIZE = 64;
var DIGEST_LENGTH = 32;
var KEY = new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var INIT = [
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
];
var MAX_HASHABLE_LENGTH = Math.pow(2, 53) - 1;

// node_modules/@aws-crypto/sha256-js/build/module/RawSha256.js
var RawSha256 = (
  /** @class */
  (function() {
    function RawSha2562() {
      this.state = Int32Array.from(INIT);
      this.temp = new Int32Array(64);
      this.buffer = new Uint8Array(64);
      this.bufferLength = 0;
      this.bytesHashed = 0;
      this.finished = false;
    }
    RawSha2562.prototype.update = function(data) {
      if (this.finished) {
        throw new Error("Attempted to update an already finished hash.");
      }
      var position = 0;
      var byteLength = data.byteLength;
      this.bytesHashed += byteLength;
      if (this.bytesHashed * 8 > MAX_HASHABLE_LENGTH) {
        throw new Error("Cannot hash more than 2^53 - 1 bits");
      }
      while (byteLength > 0) {
        this.buffer[this.bufferLength++] = data[position++];
        byteLength--;
        if (this.bufferLength === BLOCK_SIZE) {
          this.hashBuffer();
          this.bufferLength = 0;
        }
      }
    };
    RawSha2562.prototype.digest = function() {
      if (!this.finished) {
        var bitsHashed = this.bytesHashed * 8;
        var bufferView = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
        var undecoratedLength = this.bufferLength;
        bufferView.setUint8(this.bufferLength++, 128);
        if (undecoratedLength % BLOCK_SIZE >= BLOCK_SIZE - 8) {
          for (var i2 = this.bufferLength; i2 < BLOCK_SIZE; i2++) {
            bufferView.setUint8(i2, 0);
          }
          this.hashBuffer();
          this.bufferLength = 0;
        }
        for (var i2 = this.bufferLength; i2 < BLOCK_SIZE - 8; i2++) {
          bufferView.setUint8(i2, 0);
        }
        bufferView.setUint32(BLOCK_SIZE - 8, Math.floor(bitsHashed / 4294967296), true);
        bufferView.setUint32(BLOCK_SIZE - 4, bitsHashed);
        this.hashBuffer();
        this.finished = true;
      }
      var out = new Uint8Array(DIGEST_LENGTH);
      for (var i2 = 0; i2 < 8; i2++) {
        out[i2 * 4] = this.state[i2] >>> 24 & 255;
        out[i2 * 4 + 1] = this.state[i2] >>> 16 & 255;
        out[i2 * 4 + 2] = this.state[i2] >>> 8 & 255;
        out[i2 * 4 + 3] = this.state[i2] >>> 0 & 255;
      }
      return out;
    };
    RawSha2562.prototype.hashBuffer = function() {
      var _a = this, buffer = _a.buffer, state = _a.state;
      var state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3], state4 = state[4], state5 = state[5], state6 = state[6], state7 = state[7];
      for (var i2 = 0; i2 < BLOCK_SIZE; i2++) {
        if (i2 < 16) {
          this.temp[i2] = (buffer[i2 * 4] & 255) << 24 | (buffer[i2 * 4 + 1] & 255) << 16 | (buffer[i2 * 4 + 2] & 255) << 8 | buffer[i2 * 4 + 3] & 255;
        } else {
          var u2 = this.temp[i2 - 2];
          var t1_1 = (u2 >>> 17 | u2 << 15) ^ (u2 >>> 19 | u2 << 13) ^ u2 >>> 10;
          u2 = this.temp[i2 - 15];
          var t2_1 = (u2 >>> 7 | u2 << 25) ^ (u2 >>> 18 | u2 << 14) ^ u2 >>> 3;
          this.temp[i2] = (t1_1 + this.temp[i2 - 7] | 0) + (t2_1 + this.temp[i2 - 16] | 0);
        }
        var t1 = (((state4 >>> 6 | state4 << 26) ^ (state4 >>> 11 | state4 << 21) ^ (state4 >>> 25 | state4 << 7)) + (state4 & state5 ^ ~state4 & state6) | 0) + (state7 + (KEY[i2] + this.temp[i2] | 0) | 0) | 0;
        var t2 = ((state0 >>> 2 | state0 << 30) ^ (state0 >>> 13 | state0 << 19) ^ (state0 >>> 22 | state0 << 10)) + (state0 & state1 ^ state0 & state2 ^ state1 & state2) | 0;
        state7 = state6;
        state6 = state5;
        state5 = state4;
        state4 = state3 + t1 | 0;
        state3 = state2;
        state2 = state1;
        state1 = state0;
        state0 = t1 + t2 | 0;
      }
      state[0] += state0;
      state[1] += state1;
      state[2] += state2;
      state[3] += state3;
      state[4] += state4;
      state[5] += state5;
      state[6] += state6;
      state[7] += state7;
    };
    return RawSha2562;
  })()
);

// node_modules/@aws-crypto/sha256-js/build/module/jsSha256.js
var Sha2562 = (
  /** @class */
  (function() {
    function Sha2564(secret) {
      this.secret = secret;
      this.hash = new RawSha256();
      this.reset();
    }
    Sha2564.prototype.update = function(toHash) {
      if (isEmptyData(toHash) || this.error) {
        return;
      }
      try {
        this.hash.update(convertToBuffer(toHash));
      } catch (e2) {
        this.error = e2;
      }
    };
    Sha2564.prototype.digestSync = function() {
      if (this.error) {
        throw this.error;
      }
      if (this.outer) {
        if (!this.outer.finished) {
          this.outer.update(this.hash.digest());
        }
        return this.outer.digest();
      }
      return this.hash.digest();
    };
    Sha2564.prototype.digest = function() {
      return __awaiter(this, void 0, void 0, function() {
        return __generator(this, function(_a) {
          return [2, this.digestSync()];
        });
      });
    };
    Sha2564.prototype.reset = function() {
      this.hash = new RawSha256();
      if (this.secret) {
        this.outer = new RawSha256();
        var inner = bufferFromSecret(this.secret);
        var outer = new Uint8Array(BLOCK_SIZE);
        outer.set(inner);
        for (var i2 = 0; i2 < BLOCK_SIZE; i2++) {
          inner[i2] ^= 54;
          outer[i2] ^= 92;
        }
        this.hash.update(inner);
        this.outer.update(outer);
        for (var i2 = 0; i2 < inner.byteLength; i2++) {
          inner[i2] = 0;
        }
      }
    };
    return Sha2564;
  })()
);
function bufferFromSecret(secret) {
  var input = convertToBuffer(secret);
  if (input.byteLength > BLOCK_SIZE) {
    var bufferHash = new RawSha256();
    bufferHash.update(input);
    input = bufferHash.digest();
  }
  var buffer = new Uint8Array(BLOCK_SIZE);
  buffer.set(input);
  return buffer;
}

// node_modules/@aws-crypto/sha256-browser/build/module/crossPlatformSha256.js
var Sha2563 = (
  /** @class */
  (function() {
    function Sha2564(secret) {
      if (supportsWebCrypto(locateWindow())) {
        this.hash = new Sha256(secret);
      } else {
        this.hash = new Sha2562(secret);
      }
    }
    Sha2564.prototype.update = function(data, encoding) {
      this.hash.update(convertToBuffer(data));
    };
    Sha2564.prototype.digest = function() {
      return this.hash.digest();
    };
    Sha2564.prototype.reset = function() {
      this.hash.reset();
    };
    return Sha2564;
  })()
);

// node_modules/@aws-sdk/util-user-agent-browser/dist-es/index.js
var createDefaultUserAgentProvider = ({ serviceId, clientVersion }) => async (config) => {
  const navigator = typeof window !== "undefined" ? window.navigator : void 0;
  const uaString = navigator?.userAgent ?? "";
  const osName = navigator?.userAgentData?.platform ?? fallback.os(uaString) ?? "other";
  const osVersion = void 0;
  const brands = navigator?.userAgentData?.brands ?? [];
  const brand = brands[brands.length - 1];
  const browserName = brand?.brand ?? fallback.browser(uaString) ?? "unknown";
  const browserVersion = brand?.version ?? "unknown";
  const sections = [
    ["aws-sdk-js", clientVersion],
    ["ua", "2.1"],
    [`os/${osName}`, osVersion],
    ["lang/js"],
    ["md/browser", `${browserName}_${browserVersion}`]
  ];
  if (serviceId) {
    sections.push([`api/${serviceId}`, clientVersion]);
  }
  const appId = await config?.userAgentAppId?.();
  if (appId) {
    sections.push([`app/${appId}`]);
  }
  return sections;
};
var fallback = {
  os(ua) {
    if (/iPhone|iPad|iPod/.test(ua))
      return "iOS";
    if (/Macintosh|Mac OS X/.test(ua))
      return "macOS";
    if (/Windows NT/.test(ua))
      return "Windows";
    if (/Android/.test(ua))
      return "Android";
    if (/Linux/.test(ua))
      return "Linux";
    return void 0;
  },
  browser(ua) {
    if (/EdgiOS|EdgA|Edg\//.test(ua))
      return "Microsoft Edge";
    if (/Firefox\//.test(ua))
      return "Firefox";
    if (/Chrome\//.test(ua))
      return "Chrome";
    if (/Safari\//.test(ua))
      return "Safari";
    return void 0;
  }
};

// node_modules/@smithy/eventstream-codec/dist-es/Int64.js
var Int642 = class _Int64 {
  bytes;
  constructor(bytes) {
    this.bytes = bytes;
    if (bytes.byteLength !== 8) {
      throw new Error("Int64 buffers must be exactly 8 bytes");
    }
  }
  static fromNumber(number) {
    if (number > 9223372036854776e3 || number < -9223372036854776e3) {
      throw new Error(`${number} is too large (or, if negative, too small) to represent as an Int64`);
    }
    const bytes = new Uint8Array(8);
    for (let i2 = 7, remaining = Math.abs(Math.round(number)); i2 > -1 && remaining > 0; i2--, remaining /= 256) {
      bytes[i2] = remaining;
    }
    if (number < 0) {
      negate2(bytes);
    }
    return new _Int64(bytes);
  }
  valueOf() {
    const bytes = this.bytes.slice(0);
    const negative = bytes[0] & 128;
    if (negative) {
      negate2(bytes);
    }
    return parseInt(toHex(bytes), 16) * (negative ? -1 : 1);
  }
  toString() {
    return String(this.valueOf());
  }
};
function negate2(bytes) {
  for (let i2 = 0; i2 < 8; i2++) {
    bytes[i2] ^= 255;
  }
  for (let i2 = 7; i2 > -1; i2--) {
    bytes[i2]++;
    if (bytes[i2] !== 0)
      break;
  }
}

// node_modules/@smithy/eventstream-codec/dist-es/HeaderMarshaller.js
var HeaderMarshaller = class {
  toUtf8;
  fromUtf8;
  constructor(toUtf82, fromUtf85) {
    this.toUtf8 = toUtf82;
    this.fromUtf8 = fromUtf85;
  }
  format(headers) {
    const chunks = [];
    for (const headerName of Object.keys(headers)) {
      const bytes = this.fromUtf8(headerName);
      chunks.push(Uint8Array.from([bytes.byteLength]), bytes, this.formatHeaderValue(headers[headerName]));
    }
    const out = new Uint8Array(chunks.reduce((carry, bytes) => carry + bytes.byteLength, 0));
    let position = 0;
    for (const chunk of chunks) {
      out.set(chunk, position);
      position += chunk.byteLength;
    }
    return out;
  }
  formatHeaderValue(header) {
    switch (header.type) {
      case "boolean":
        return Uint8Array.from([header.value ? 0 : 1]);
      case "byte":
        return Uint8Array.from([2, header.value]);
      case "short":
        const shortView = new DataView(new ArrayBuffer(3));
        shortView.setUint8(0, 3);
        shortView.setInt16(1, header.value, false);
        return new Uint8Array(shortView.buffer);
      case "integer":
        const intView = new DataView(new ArrayBuffer(5));
        intView.setUint8(0, 4);
        intView.setInt32(1, header.value, false);
        return new Uint8Array(intView.buffer);
      case "long":
        const longBytes = new Uint8Array(9);
        longBytes[0] = 5;
        longBytes.set(header.value.bytes, 1);
        return longBytes;
      case "binary":
        const binView = new DataView(new ArrayBuffer(3 + header.value.byteLength));
        binView.setUint8(0, 6);
        binView.setUint16(1, header.value.byteLength, false);
        const binBytes = new Uint8Array(binView.buffer);
        binBytes.set(header.value, 3);
        return binBytes;
      case "string":
        const utf8Bytes = this.fromUtf8(header.value);
        const strView = new DataView(new ArrayBuffer(3 + utf8Bytes.byteLength));
        strView.setUint8(0, 7);
        strView.setUint16(1, utf8Bytes.byteLength, false);
        const strBytes = new Uint8Array(strView.buffer);
        strBytes.set(utf8Bytes, 3);
        return strBytes;
      case "timestamp":
        const tsBytes = new Uint8Array(9);
        tsBytes[0] = 8;
        tsBytes.set(Int642.fromNumber(header.value.valueOf()).bytes, 1);
        return tsBytes;
      case "uuid":
        if (!UUID_PATTERN2.test(header.value)) {
          throw new Error(`Invalid UUID received: ${header.value}`);
        }
        const uuidBytes = new Uint8Array(17);
        uuidBytes[0] = 9;
        uuidBytes.set(fromHex(header.value.replace(/\-/g, "")), 1);
        return uuidBytes;
    }
  }
  parse(headers) {
    const out = {};
    let position = 0;
    while (position < headers.byteLength) {
      const nameLength = headers.getUint8(position++);
      const name = this.toUtf8(new Uint8Array(headers.buffer, headers.byteOffset + position, nameLength));
      position += nameLength;
      switch (headers.getUint8(position++)) {
        case 0:
          out[name] = {
            type: BOOLEAN_TAG,
            value: true
          };
          break;
        case 1:
          out[name] = {
            type: BOOLEAN_TAG,
            value: false
          };
          break;
        case 2:
          out[name] = {
            type: BYTE_TAG,
            value: headers.getInt8(position++)
          };
          break;
        case 3:
          out[name] = {
            type: SHORT_TAG,
            value: headers.getInt16(position, false)
          };
          position += 2;
          break;
        case 4:
          out[name] = {
            type: INT_TAG,
            value: headers.getInt32(position, false)
          };
          position += 4;
          break;
        case 5:
          out[name] = {
            type: LONG_TAG,
            value: new Int642(new Uint8Array(headers.buffer, headers.byteOffset + position, 8))
          };
          position += 8;
          break;
        case 6:
          const binaryLength = headers.getUint16(position, false);
          position += 2;
          out[name] = {
            type: BINARY_TAG,
            value: new Uint8Array(headers.buffer, headers.byteOffset + position, binaryLength)
          };
          position += binaryLength;
          break;
        case 7:
          const stringLength = headers.getUint16(position, false);
          position += 2;
          out[name] = {
            type: STRING_TAG,
            value: this.toUtf8(new Uint8Array(headers.buffer, headers.byteOffset + position, stringLength))
          };
          position += stringLength;
          break;
        case 8:
          out[name] = {
            type: TIMESTAMP_TAG,
            value: new Date(new Int642(new Uint8Array(headers.buffer, headers.byteOffset + position, 8)).valueOf())
          };
          position += 8;
          break;
        case 9:
          const uuidBytes = new Uint8Array(headers.buffer, headers.byteOffset + position, 16);
          position += 16;
          out[name] = {
            type: UUID_TAG,
            value: `${toHex(uuidBytes.subarray(0, 4))}-${toHex(uuidBytes.subarray(4, 6))}-${toHex(uuidBytes.subarray(6, 8))}-${toHex(uuidBytes.subarray(8, 10))}-${toHex(uuidBytes.subarray(10))}`
          };
          break;
        default:
          throw new Error(`Unrecognized header type tag`);
      }
    }
    return out;
  }
};
var HEADER_VALUE_TYPE2;
(function(HEADER_VALUE_TYPE3) {
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["boolTrue"] = 0] = "boolTrue";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["boolFalse"] = 1] = "boolFalse";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["byte"] = 2] = "byte";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["short"] = 3] = "short";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["integer"] = 4] = "integer";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["long"] = 5] = "long";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["byteArray"] = 6] = "byteArray";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["string"] = 7] = "string";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["timestamp"] = 8] = "timestamp";
  HEADER_VALUE_TYPE3[HEADER_VALUE_TYPE3["uuid"] = 9] = "uuid";
})(HEADER_VALUE_TYPE2 || (HEADER_VALUE_TYPE2 = {}));
var BOOLEAN_TAG = "boolean";
var BYTE_TAG = "byte";
var SHORT_TAG = "short";
var INT_TAG = "integer";
var LONG_TAG = "long";
var BINARY_TAG = "binary";
var STRING_TAG = "string";
var TIMESTAMP_TAG = "timestamp";
var UUID_TAG = "uuid";
var UUID_PATTERN2 = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

// node_modules/@smithy/eventstream-codec/dist-es/splitMessage.js
var PRELUDE_MEMBER_LENGTH = 4;
var PRELUDE_LENGTH = PRELUDE_MEMBER_LENGTH * 2;
var CHECKSUM_LENGTH = 4;
var MINIMUM_MESSAGE_LENGTH = PRELUDE_LENGTH + CHECKSUM_LENGTH * 2;
function splitMessage({ byteLength, byteOffset, buffer }) {
  if (byteLength < MINIMUM_MESSAGE_LENGTH) {
    throw new Error("Provided message too short to accommodate event stream message overhead");
  }
  const view = new DataView(buffer, byteOffset, byteLength);
  const messageLength = view.getUint32(0, false);
  if (byteLength !== messageLength) {
    throw new Error("Reported message length does not match received message length");
  }
  const headerLength = view.getUint32(PRELUDE_MEMBER_LENGTH, false);
  const expectedPreludeChecksum = view.getUint32(PRELUDE_LENGTH, false);
  const expectedMessageChecksum = view.getUint32(byteLength - CHECKSUM_LENGTH, false);
  const checksummer = new Crc32().update(new Uint8Array(buffer, byteOffset, PRELUDE_LENGTH));
  if (expectedPreludeChecksum !== checksummer.digest()) {
    throw new Error(`The prelude checksum specified in the message (${expectedPreludeChecksum}) does not match the calculated CRC32 checksum (${checksummer.digest()})`);
  }
  checksummer.update(new Uint8Array(buffer, byteOffset + PRELUDE_LENGTH, byteLength - (PRELUDE_LENGTH + CHECKSUM_LENGTH)));
  if (expectedMessageChecksum !== checksummer.digest()) {
    throw new Error(`The message checksum (${checksummer.digest()}) did not match the expected value of ${expectedMessageChecksum}`);
  }
  return {
    headers: new DataView(buffer, byteOffset + PRELUDE_LENGTH + CHECKSUM_LENGTH, headerLength),
    body: new Uint8Array(buffer, byteOffset + PRELUDE_LENGTH + CHECKSUM_LENGTH + headerLength, messageLength - headerLength - (PRELUDE_LENGTH + CHECKSUM_LENGTH + CHECKSUM_LENGTH))
  };
}

// node_modules/@smithy/eventstream-codec/dist-es/EventStreamCodec.js
var EventStreamCodec = class {
  headerMarshaller;
  messageBuffer;
  isEndOfStream;
  constructor(toUtf82, fromUtf85) {
    this.headerMarshaller = new HeaderMarshaller(toUtf82, fromUtf85);
    this.messageBuffer = [];
    this.isEndOfStream = false;
  }
  feed(message) {
    this.messageBuffer.push(this.decode(message));
  }
  endOfStream() {
    this.isEndOfStream = true;
  }
  getMessage() {
    const message = this.messageBuffer.pop();
    const isEndOfStream = this.isEndOfStream;
    return {
      getMessage() {
        return message;
      },
      isEndOfStream() {
        return isEndOfStream;
      }
    };
  }
  getAvailableMessages() {
    const messages = this.messageBuffer;
    this.messageBuffer = [];
    const isEndOfStream = this.isEndOfStream;
    return {
      getMessages() {
        return messages;
      },
      isEndOfStream() {
        return isEndOfStream;
      }
    };
  }
  encode({ headers: rawHeaders, body }) {
    const headers = this.headerMarshaller.format(rawHeaders);
    const length = headers.byteLength + body.byteLength + 16;
    const out = new Uint8Array(length);
    const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const checksum = new Crc32();
    view.setUint32(0, length, false);
    view.setUint32(4, headers.byteLength, false);
    view.setUint32(8, checksum.update(out.subarray(0, 8)).digest(), false);
    out.set(headers, 12);
    out.set(body, headers.byteLength + 12);
    view.setUint32(length - 4, checksum.update(out.subarray(8, length - 4)).digest(), false);
    return out;
  }
  decode(message) {
    const { headers, body } = splitMessage(message);
    return { headers: this.headerMarshaller.parse(headers), body };
  }
  formatHeaders(rawHeaders) {
    return this.headerMarshaller.format(rawHeaders);
  }
};

// node_modules/@smithy/eventstream-codec/dist-es/MessageDecoderStream.js
var MessageDecoderStream = class {
  options;
  constructor(options) {
    this.options = options;
  }
  [Symbol.asyncIterator]() {
    return this.asyncIterator();
  }
  async *asyncIterator() {
    for await (const bytes of this.options.inputStream) {
      const decoded = this.options.decoder.decode(bytes);
      yield decoded;
    }
  }
};

// node_modules/@smithy/eventstream-codec/dist-es/MessageEncoderStream.js
var MessageEncoderStream = class {
  options;
  constructor(options) {
    this.options = options;
  }
  [Symbol.asyncIterator]() {
    return this.asyncIterator();
  }
  async *asyncIterator() {
    for await (const msg of this.options.messageStream) {
      const encoded = this.options.encoder.encode(msg);
      yield encoded;
    }
    if (this.options.includeEndFrame) {
      yield new Uint8Array(0);
    }
  }
};

// node_modules/@smithy/eventstream-codec/dist-es/SmithyMessageDecoderStream.js
var SmithyMessageDecoderStream = class {
  options;
  constructor(options) {
    this.options = options;
  }
  [Symbol.asyncIterator]() {
    return this.asyncIterator();
  }
  async *asyncIterator() {
    for await (const message of this.options.messageStream) {
      const deserialized = await this.options.deserializer(message);
      if (deserialized === void 0)
        continue;
      yield deserialized;
    }
  }
};

// node_modules/@smithy/eventstream-codec/dist-es/SmithyMessageEncoderStream.js
var SmithyMessageEncoderStream = class {
  options;
  constructor(options) {
    this.options = options;
  }
  [Symbol.asyncIterator]() {
    return this.asyncIterator();
  }
  async *asyncIterator() {
    for await (const chunk of this.options.inputStream) {
      const payloadBuf = this.options.serializer(chunk);
      yield payloadBuf;
    }
  }
};

// node_modules/@smithy/eventstream-serde-universal/dist-es/getChunkedStream.js
function getChunkedStream(source) {
  let currentMessageTotalLength = 0;
  let currentMessagePendingLength = 0;
  let currentMessage = null;
  let messageLengthBuffer = null;
  const allocateMessage = (size) => {
    if (typeof size !== "number") {
      throw new Error("Attempted to allocate an event message where size was not a number: " + size);
    }
    currentMessageTotalLength = size;
    currentMessagePendingLength = 4;
    currentMessage = new Uint8Array(size);
    const currentMessageView = new DataView(currentMessage.buffer);
    currentMessageView.setUint32(0, size, false);
  };
  const iterator = async function* () {
    const sourceIterator = source[Symbol.asyncIterator]();
    while (true) {
      const { value, done } = await sourceIterator.next();
      if (done) {
        if (!currentMessageTotalLength) {
          return;
        } else if (currentMessageTotalLength === currentMessagePendingLength) {
          yield currentMessage;
        } else {
          throw new Error("Truncated event message received.");
        }
        return;
      }
      const chunkLength = value.length;
      let currentOffset = 0;
      while (currentOffset < chunkLength) {
        if (!currentMessage) {
          const bytesRemaining = chunkLength - currentOffset;
          if (!messageLengthBuffer) {
            messageLengthBuffer = new Uint8Array(4);
          }
          const numBytesForTotal = Math.min(4 - currentMessagePendingLength, bytesRemaining);
          messageLengthBuffer.set(value.slice(currentOffset, currentOffset + numBytesForTotal), currentMessagePendingLength);
          currentMessagePendingLength += numBytesForTotal;
          currentOffset += numBytesForTotal;
          if (currentMessagePendingLength < 4) {
            break;
          }
          allocateMessage(new DataView(messageLengthBuffer.buffer).getUint32(0, false));
          messageLengthBuffer = null;
        }
        const numBytesToWrite = Math.min(currentMessageTotalLength - currentMessagePendingLength, chunkLength - currentOffset);
        currentMessage.set(value.slice(currentOffset, currentOffset + numBytesToWrite), currentMessagePendingLength);
        currentMessagePendingLength += numBytesToWrite;
        currentOffset += numBytesToWrite;
        if (currentMessageTotalLength && currentMessageTotalLength === currentMessagePendingLength) {
          yield currentMessage;
          currentMessage = null;
          currentMessageTotalLength = 0;
          currentMessagePendingLength = 0;
        }
      }
    }
  };
  return {
    [Symbol.asyncIterator]: iterator
  };
}

// node_modules/@smithy/eventstream-serde-universal/dist-es/getUnmarshalledStream.js
function getMessageUnmarshaller(deserializer, toUtf82) {
  return async function(message) {
    const { value: messageType } = message.headers[":message-type"];
    if (messageType === "error") {
      const unmodeledError = new Error(message.headers[":error-message"].value || "UnknownError");
      unmodeledError.name = message.headers[":error-code"].value;
      throw unmodeledError;
    } else if (messageType === "exception") {
      const code = message.headers[":exception-type"].value;
      const exception = { [code]: message };
      const deserializedException = await deserializer(exception);
      if (deserializedException.$unknown) {
        const error = new Error(toUtf82(message.body));
        error.name = code;
        throw error;
      }
      throw deserializedException[code];
    } else if (messageType === "event") {
      const event = {
        [message.headers[":event-type"].value]: message
      };
      const deserialized = await deserializer(event);
      if (deserialized.$unknown)
        return;
      return deserialized;
    } else {
      throw Error(`Unrecognizable event type: ${message.headers[":event-type"].value}`);
    }
  };
}

// node_modules/@smithy/eventstream-serde-universal/dist-es/EventStreamMarshaller.js
var EventStreamMarshaller = class {
  eventStreamCodec;
  utfEncoder;
  constructor({ utf8Encoder, utf8Decoder }) {
    this.eventStreamCodec = new EventStreamCodec(utf8Encoder, utf8Decoder);
    this.utfEncoder = utf8Encoder;
  }
  deserialize(body, deserializer) {
    const inputStream = getChunkedStream(body);
    return new SmithyMessageDecoderStream({
      messageStream: new MessageDecoderStream({ inputStream, decoder: this.eventStreamCodec }),
      deserializer: getMessageUnmarshaller(deserializer, this.utfEncoder)
    });
  }
  serialize(inputStream, serializer) {
    return new MessageEncoderStream({
      messageStream: new SmithyMessageEncoderStream({ inputStream, serializer }),
      encoder: this.eventStreamCodec,
      includeEndFrame: true
    });
  }
};

// node_modules/@smithy/eventstream-serde-browser/dist-es/utils.js
var readableStreamtoIterable = (readableStream) => ({
  [Symbol.asyncIterator]: async function* () {
    const reader = readableStream.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done)
          return;
        yield value;
      }
    } finally {
      reader.releaseLock();
    }
  }
});
var iterableToReadableStream = (asyncIterable) => {
  const iterator = asyncIterable[Symbol.asyncIterator]();
  return new ReadableStream({
    async pull(controller) {
      const { done, value } = await iterator.next();
      if (done) {
        return controller.close();
      }
      controller.enqueue(value);
    }
  });
};

// node_modules/@smithy/eventstream-serde-browser/dist-es/EventStreamMarshaller.js
var EventStreamMarshaller2 = class {
  universalMarshaller;
  constructor({ utf8Encoder, utf8Decoder }) {
    this.universalMarshaller = new EventStreamMarshaller({
      utf8Decoder,
      utf8Encoder
    });
  }
  deserialize(body, deserializer) {
    const bodyIterable = isReadableStream2(body) ? readableStreamtoIterable(body) : body;
    return this.universalMarshaller.deserialize(bodyIterable, deserializer);
  }
  serialize(input, serializer) {
    const serialziedIterable = this.universalMarshaller.serialize(input, serializer);
    return typeof ReadableStream === "function" ? iterableToReadableStream(serialziedIterable) : serialziedIterable;
  }
};
var isReadableStream2 = (body) => typeof ReadableStream === "function" && body instanceof ReadableStream;

// node_modules/@smithy/eventstream-serde-browser/dist-es/provider.js
var eventStreamSerdeProvider = (options) => new EventStreamMarshaller2(options);

// node_modules/@smithy/chunked-blob-reader/dist-es/index.js
async function blobReader(blob, onChunk, chunkSize = 1024 * 1024) {
  const size = blob.size;
  let totalBytesRead = 0;
  while (totalBytesRead < size) {
    const slice = blob.slice(totalBytesRead, Math.min(size, totalBytesRead + chunkSize));
    onChunk(new Uint8Array(await slice.arrayBuffer()));
    totalBytesRead += slice.size;
  }
}

// node_modules/@smithy/hash-blob-browser/dist-es/index.js
var blobHasher = async function blobHasher2(hashCtor, blob) {
  const hash = new hashCtor();
  await blobReader(blob, (chunk) => {
    hash.update(chunk);
  });
  return hash.digest();
};

// node_modules/@smithy/invalid-dependency/dist-es/invalidProvider.js
var invalidProvider = (message) => () => Promise.reject(message);

// node_modules/@smithy/md5-js/dist-es/index.js
init_dist_es();

// node_modules/@smithy/md5-js/dist-es/constants.js
var BLOCK_SIZE2 = 64;
var DIGEST_LENGTH2 = 16;
var INIT2 = [1732584193, 4023233417, 2562383102, 271733878];

// node_modules/@smithy/md5-js/dist-es/index.js
var Md5 = class {
  state;
  buffer;
  bufferLength;
  bytesHashed;
  finished;
  constructor() {
    this.reset();
  }
  update(sourceData) {
    if (isEmptyData3(sourceData)) {
      return;
    } else if (this.finished) {
      throw new Error("Attempted to update an already finished hash.");
    }
    const data = convertToBuffer3(sourceData);
    let position = 0;
    let { byteLength } = data;
    this.bytesHashed += byteLength;
    while (byteLength > 0) {
      this.buffer.setUint8(this.bufferLength++, data[position++]);
      byteLength--;
      if (this.bufferLength === BLOCK_SIZE2) {
        this.hashBuffer();
        this.bufferLength = 0;
      }
    }
  }
  async digest() {
    if (!this.finished) {
      const { buffer, bufferLength: undecoratedLength, bytesHashed } = this;
      const bitsHashed = bytesHashed * 8;
      buffer.setUint8(this.bufferLength++, 128);
      if (undecoratedLength % BLOCK_SIZE2 >= BLOCK_SIZE2 - 8) {
        for (let i2 = this.bufferLength; i2 < BLOCK_SIZE2; i2++) {
          buffer.setUint8(i2, 0);
        }
        this.hashBuffer();
        this.bufferLength = 0;
      }
      for (let i2 = this.bufferLength; i2 < BLOCK_SIZE2 - 8; i2++) {
        buffer.setUint8(i2, 0);
      }
      buffer.setUint32(BLOCK_SIZE2 - 8, bitsHashed >>> 0, true);
      buffer.setUint32(BLOCK_SIZE2 - 4, Math.floor(bitsHashed / 4294967296), true);
      this.hashBuffer();
      this.finished = true;
    }
    const out = new DataView(new ArrayBuffer(DIGEST_LENGTH2));
    for (let i2 = 0; i2 < 4; i2++) {
      out.setUint32(i2 * 4, this.state[i2], true);
    }
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  }
  hashBuffer() {
    const { buffer, state } = this;
    let a2 = state[0], b2 = state[1], c2 = state[2], d2 = state[3];
    a2 = ff(a2, b2, c2, d2, buffer.getUint32(0, true), 7, 3614090360);
    d2 = ff(d2, a2, b2, c2, buffer.getUint32(4, true), 12, 3905402710);
    c2 = ff(c2, d2, a2, b2, buffer.getUint32(8, true), 17, 606105819);
    b2 = ff(b2, c2, d2, a2, buffer.getUint32(12, true), 22, 3250441966);
    a2 = ff(a2, b2, c2, d2, buffer.getUint32(16, true), 7, 4118548399);
    d2 = ff(d2, a2, b2, c2, buffer.getUint32(20, true), 12, 1200080426);
    c2 = ff(c2, d2, a2, b2, buffer.getUint32(24, true), 17, 2821735955);
    b2 = ff(b2, c2, d2, a2, buffer.getUint32(28, true), 22, 4249261313);
    a2 = ff(a2, b2, c2, d2, buffer.getUint32(32, true), 7, 1770035416);
    d2 = ff(d2, a2, b2, c2, buffer.getUint32(36, true), 12, 2336552879);
    c2 = ff(c2, d2, a2, b2, buffer.getUint32(40, true), 17, 4294925233);
    b2 = ff(b2, c2, d2, a2, buffer.getUint32(44, true), 22, 2304563134);
    a2 = ff(a2, b2, c2, d2, buffer.getUint32(48, true), 7, 1804603682);
    d2 = ff(d2, a2, b2, c2, buffer.getUint32(52, true), 12, 4254626195);
    c2 = ff(c2, d2, a2, b2, buffer.getUint32(56, true), 17, 2792965006);
    b2 = ff(b2, c2, d2, a2, buffer.getUint32(60, true), 22, 1236535329);
    a2 = gg(a2, b2, c2, d2, buffer.getUint32(4, true), 5, 4129170786);
    d2 = gg(d2, a2, b2, c2, buffer.getUint32(24, true), 9, 3225465664);
    c2 = gg(c2, d2, a2, b2, buffer.getUint32(44, true), 14, 643717713);
    b2 = gg(b2, c2, d2, a2, buffer.getUint32(0, true), 20, 3921069994);
    a2 = gg(a2, b2, c2, d2, buffer.getUint32(20, true), 5, 3593408605);
    d2 = gg(d2, a2, b2, c2, buffer.getUint32(40, true), 9, 38016083);
    c2 = gg(c2, d2, a2, b2, buffer.getUint32(60, true), 14, 3634488961);
    b2 = gg(b2, c2, d2, a2, buffer.getUint32(16, true), 20, 3889429448);
    a2 = gg(a2, b2, c2, d2, buffer.getUint32(36, true), 5, 568446438);
    d2 = gg(d2, a2, b2, c2, buffer.getUint32(56, true), 9, 3275163606);
    c2 = gg(c2, d2, a2, b2, buffer.getUint32(12, true), 14, 4107603335);
    b2 = gg(b2, c2, d2, a2, buffer.getUint32(32, true), 20, 1163531501);
    a2 = gg(a2, b2, c2, d2, buffer.getUint32(52, true), 5, 2850285829);
    d2 = gg(d2, a2, b2, c2, buffer.getUint32(8, true), 9, 4243563512);
    c2 = gg(c2, d2, a2, b2, buffer.getUint32(28, true), 14, 1735328473);
    b2 = gg(b2, c2, d2, a2, buffer.getUint32(48, true), 20, 2368359562);
    a2 = hh(a2, b2, c2, d2, buffer.getUint32(20, true), 4, 4294588738);
    d2 = hh(d2, a2, b2, c2, buffer.getUint32(32, true), 11, 2272392833);
    c2 = hh(c2, d2, a2, b2, buffer.getUint32(44, true), 16, 1839030562);
    b2 = hh(b2, c2, d2, a2, buffer.getUint32(56, true), 23, 4259657740);
    a2 = hh(a2, b2, c2, d2, buffer.getUint32(4, true), 4, 2763975236);
    d2 = hh(d2, a2, b2, c2, buffer.getUint32(16, true), 11, 1272893353);
    c2 = hh(c2, d2, a2, b2, buffer.getUint32(28, true), 16, 4139469664);
    b2 = hh(b2, c2, d2, a2, buffer.getUint32(40, true), 23, 3200236656);
    a2 = hh(a2, b2, c2, d2, buffer.getUint32(52, true), 4, 681279174);
    d2 = hh(d2, a2, b2, c2, buffer.getUint32(0, true), 11, 3936430074);
    c2 = hh(c2, d2, a2, b2, buffer.getUint32(12, true), 16, 3572445317);
    b2 = hh(b2, c2, d2, a2, buffer.getUint32(24, true), 23, 76029189);
    a2 = hh(a2, b2, c2, d2, buffer.getUint32(36, true), 4, 3654602809);
    d2 = hh(d2, a2, b2, c2, buffer.getUint32(48, true), 11, 3873151461);
    c2 = hh(c2, d2, a2, b2, buffer.getUint32(60, true), 16, 530742520);
    b2 = hh(b2, c2, d2, a2, buffer.getUint32(8, true), 23, 3299628645);
    a2 = ii(a2, b2, c2, d2, buffer.getUint32(0, true), 6, 4096336452);
    d2 = ii(d2, a2, b2, c2, buffer.getUint32(28, true), 10, 1126891415);
    c2 = ii(c2, d2, a2, b2, buffer.getUint32(56, true), 15, 2878612391);
    b2 = ii(b2, c2, d2, a2, buffer.getUint32(20, true), 21, 4237533241);
    a2 = ii(a2, b2, c2, d2, buffer.getUint32(48, true), 6, 1700485571);
    d2 = ii(d2, a2, b2, c2, buffer.getUint32(12, true), 10, 2399980690);
    c2 = ii(c2, d2, a2, b2, buffer.getUint32(40, true), 15, 4293915773);
    b2 = ii(b2, c2, d2, a2, buffer.getUint32(4, true), 21, 2240044497);
    a2 = ii(a2, b2, c2, d2, buffer.getUint32(32, true), 6, 1873313359);
    d2 = ii(d2, a2, b2, c2, buffer.getUint32(60, true), 10, 4264355552);
    c2 = ii(c2, d2, a2, b2, buffer.getUint32(24, true), 15, 2734768916);
    b2 = ii(b2, c2, d2, a2, buffer.getUint32(52, true), 21, 1309151649);
    a2 = ii(a2, b2, c2, d2, buffer.getUint32(16, true), 6, 4149444226);
    d2 = ii(d2, a2, b2, c2, buffer.getUint32(44, true), 10, 3174756917);
    c2 = ii(c2, d2, a2, b2, buffer.getUint32(8, true), 15, 718787259);
    b2 = ii(b2, c2, d2, a2, buffer.getUint32(36, true), 21, 3951481745);
    state[0] = a2 + state[0] & 4294967295;
    state[1] = b2 + state[1] & 4294967295;
    state[2] = c2 + state[2] & 4294967295;
    state[3] = d2 + state[3] & 4294967295;
  }
  reset() {
    this.state = Uint32Array.from(INIT2);
    this.buffer = new DataView(new ArrayBuffer(BLOCK_SIZE2));
    this.bufferLength = 0;
    this.bytesHashed = 0;
    this.finished = false;
  }
};
function cmn(q2, a2, b2, x2, s2, t2) {
  a2 = (a2 + q2 & 4294967295) + (x2 + t2 & 4294967295) & 4294967295;
  return (a2 << s2 | a2 >>> 32 - s2) + b2 & 4294967295;
}
function ff(a2, b2, c2, d2, x2, s2, t2) {
  return cmn(b2 & c2 | ~b2 & d2, a2, b2, x2, s2, t2);
}
function gg(a2, b2, c2, d2, x2, s2, t2) {
  return cmn(b2 & d2 | c2 & ~d2, a2, b2, x2, s2, t2);
}
function hh(a2, b2, c2, d2, x2, s2, t2) {
  return cmn(b2 ^ c2 ^ d2, a2, b2, x2, s2, t2);
}
function ii(a2, b2, c2, d2, x2, s2, t2) {
  return cmn(c2 ^ (b2 | ~d2), a2, b2, x2, s2, t2);
}
function isEmptyData3(data) {
  if (typeof data === "string") {
    return data.length === 0;
  }
  return data.byteLength === 0;
}
function convertToBuffer3(data) {
  if (typeof data === "string") {
    return fromUtf8(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
  }
  return new Uint8Array(data);
}

// node_modules/@aws-sdk/client-s3/dist-es/runtimeConfig.shared.js
init_dist_es();
var getRuntimeConfig = (config) => {
  return {
    apiVersion: "2006-03-01",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    extensions: config?.extensions ?? [],
    getAwsChunkedEncodingStream: config?.getAwsChunkedEncodingStream ?? getAwsChunkedEncodingStream,
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultS3HttpAuthSchemeProvider,
    httpAuthSchemes: config?.httpAuthSchemes ?? [
      {
        schemeId: "aws.auth#sigv4",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
        signer: new AwsSdkSigV4Signer()
      },
      {
        schemeId: "aws.auth#sigv4a",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4a"),
        signer: new AwsSdkSigV4ASigner()
      }
    ],
    logger: config?.logger ?? new NoOpLogger(),
    sdkStreamMixin: config?.sdkStreamMixin ?? sdkStreamMixin,
    serviceId: config?.serviceId ?? "S3",
    signerConstructor: config?.signerConstructor ?? SignatureV4MultiRegion,
    signingEscapePath: config?.signingEscapePath ?? false,
    urlParser: config?.urlParser ?? parseUrl,
    useArnRegion: config?.useArnRegion ?? void 0,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// node_modules/@smithy/util-defaults-mode-browser/dist-es/constants.js
var DEFAULTS_MODE_OPTIONS = ["in-region", "cross-region", "mobile", "standard", "legacy"];

// node_modules/@smithy/util-defaults-mode-browser/dist-es/resolveDefaultsModeConfig.js
var resolveDefaultsModeConfig = ({ defaultsMode } = {}) => memoize(async () => {
  const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
  switch (mode?.toLowerCase()) {
    case "auto":
      return Promise.resolve(useMobileConfiguration() ? "mobile" : "standard");
    case "mobile":
    case "in-region":
    case "cross-region":
    case "standard":
    case "legacy":
      return Promise.resolve(mode?.toLocaleLowerCase());
    case void 0:
      return Promise.resolve("legacy");
    default:
      throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
  }
});
var useMobileConfiguration = () => {
  const navigator = window?.navigator;
  if (navigator?.connection) {
    const { effectiveType, rtt, downlink } = navigator?.connection;
    const slow = typeof effectiveType === "string" && effectiveType !== "4g" || Number(rtt) > 100 || Number(downlink) < 10;
    if (slow) {
      return true;
    }
  }
  return navigator?.userAgentData?.mobile || typeof navigator?.maxTouchPoints === "number" && navigator?.maxTouchPoints > 1;
};

// node_modules/@aws-sdk/client-s3/dist-es/runtimeConfig.browser.js
var getRuntimeConfig2 = (config) => {
  const defaultsMode = resolveDefaultsModeConfig(config);
  const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
  const clientSharedValues = getRuntimeConfig(config);
  return {
    ...clientSharedValues,
    ...config,
    runtime: "browser",
    defaultsMode,
    bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
    credentialDefaultProvider: config?.credentialDefaultProvider ?? ((_) => () => Promise.reject(new Error("Credential is missing"))),
    defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
    eventStreamSerdeProvider: config?.eventStreamSerdeProvider ?? eventStreamSerdeProvider,
    maxAttempts: config?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
    md5: config?.md5 ?? Md5,
    region: config?.region ?? invalidProvider("Region is missing"),
    requestHandler: FetchHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
    retryMode: config?.retryMode ?? (async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE),
    sha1: config?.sha1 ?? Sha12,
    sha256: config?.sha256 ?? Sha2563,
    streamCollector: config?.streamCollector ?? streamCollector,
    streamHasher: config?.streamHasher ?? blobHasher,
    useDualstackEndpoint: config?.useDualstackEndpoint ?? (() => Promise.resolve(DEFAULT_USE_DUALSTACK_ENDPOINT)),
    useFipsEndpoint: config?.useFipsEndpoint ?? (() => Promise.resolve(DEFAULT_USE_FIPS_ENDPOINT))
  };
};

// node_modules/@aws-sdk/region-config-resolver/dist-es/extensions/index.js
var getAwsRegionExtensionConfiguration = (runtimeConfig) => {
  return {
    setRegion(region) {
      runtimeConfig.region = region;
    },
    region() {
      return runtimeConfig.region;
    }
  };
};
var resolveAwsRegionExtensionConfiguration = (awsRegionExtensionConfiguration) => {
  return {
    region: awsRegionExtensionConfiguration.region()
  };
};

// node_modules/@aws-sdk/client-s3/dist-es/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration = (runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
};
var resolveHttpAuthRuntimeConfig = (config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
};

// node_modules/@aws-sdk/client-s3/dist-es/runtimeExtensions.js
var resolveRuntimeExtensions = (runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
};

// node_modules/@aws-sdk/client-s3/dist-es/S3Client.js
var S3Client = class extends Client {
  config;
  constructor(...[configuration]) {
    const _config_0 = getRuntimeConfig2(configuration || {});
    super(_config_0);
    this.initConfig = _config_0;
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = resolveUserAgentConfig(_config_1);
    const _config_3 = resolveFlexibleChecksumsConfig(_config_2);
    const _config_4 = resolveRetryConfig(_config_3);
    const _config_5 = resolveRegionConfig(_config_4);
    const _config_6 = resolveHostHeaderConfig(_config_5);
    const _config_7 = resolveEndpointConfig(_config_6);
    const _config_8 = resolveEventStreamSerdeConfig(_config_7);
    const _config_9 = resolveHttpAuthSchemeConfig(_config_8);
    const _config_10 = resolveS3Config(_config_9, { session: [() => this, CreateSessionCommand] });
    const _config_11 = resolveRuntimeExtensions(_config_10, configuration?.extensions || []);
    this.config = _config_11;
    this.middlewareStack.use(getUserAgentPlugin(this.config));
    this.middlewareStack.use(getRetryPlugin(this.config));
    this.middlewareStack.use(getContentLengthPlugin(this.config));
    this.middlewareStack.use(getHostHeaderPlugin(this.config));
    this.middlewareStack.use(getLoggerPlugin(this.config));
    this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
    this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
      httpAuthSchemeParametersProvider: defaultS3HttpAuthSchemeParametersProvider,
      identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
        "aws.auth#sigv4": config.credentials,
        "aws.auth#sigv4a": config.credentials
      })
    }));
    this.middlewareStack.use(getHttpSigningPlugin(this.config));
    this.middlewareStack.use(getValidateBucketNamePlugin(this.config));
    this.middlewareStack.use(getAddExpectContinuePlugin(this.config));
    this.middlewareStack.use(getRegionRedirectMiddlewarePlugin(this.config));
    this.middlewareStack.use(getS3ExpressPlugin(this.config));
    this.middlewareStack.use(getS3ExpressHttpSigningPlugin(this.config));
  }
  destroy() {
    super.destroy();
  }
};

// node_modules/@aws-sdk/middleware-ssec/dist-es/index.js
function ssecMiddleware(options) {
  return (next) => async (args) => {
    const input = { ...args.input };
    const properties = [
      {
        target: "SSECustomerKey",
        hash: "SSECustomerKeyMD5"
      },
      {
        target: "CopySourceSSECustomerKey",
        hash: "CopySourceSSECustomerKeyMD5"
      }
    ];
    for (const prop of properties) {
      const value = input[prop.target];
      if (value) {
        let valueForHash;
        if (typeof value === "string") {
          if (isValidBase64EncodedSSECustomerKey(value, options)) {
            valueForHash = options.base64Decoder(value);
          } else {
            valueForHash = options.utf8Decoder(value);
            input[prop.target] = options.base64Encoder(valueForHash);
          }
        } else {
          valueForHash = ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : new Uint8Array(value);
          input[prop.target] = options.base64Encoder(valueForHash);
        }
        const hash = new options.md5();
        hash.update(valueForHash);
        input[prop.hash] = options.base64Encoder(await hash.digest());
      }
    }
    return next({
      ...args,
      input
    });
  };
}
var ssecMiddlewareOptions = {
  name: "ssecMiddleware",
  step: "initialize",
  tags: ["SSE"],
  override: true
};
var getSsecPlugin = (config) => ({
  applyToStack: (clientStack) => {
    clientStack.add(ssecMiddleware(config), ssecMiddlewareOptions);
  }
});
function isValidBase64EncodedSSECustomerKey(str, options) {
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (!base64Regex.test(str))
    return false;
  try {
    const decodedBytes = options.base64Decoder(str);
    return decodedBytes.length === 32;
  } catch {
    return false;
  }
}

// node_modules/@aws-sdk/client-s3/dist-es/commands/PutObjectCommand.js
var PutObjectCommand = class extends Command.classBuilder().ep({
  ...commonParams,
  Bucket: { type: "contextParams", name: "Bucket" },
  Key: { type: "contextParams", name: "Key" }
}).m(function(Command2, cs2, config, o2) {
  return [
    getSerdePlugin(config, this.serialize, this.deserialize),
    getEndpointPlugin(config, Command2.getEndpointParameterInstructions()),
    getFlexibleChecksumsPlugin(config, {
      requestAlgorithmMember: { httpHeader: "x-amz-sdk-checksum-algorithm", name: "ChecksumAlgorithm" },
      requestChecksumRequired: false
    }),
    getCheckContentLengthHeaderPlugin(config),
    getThrow200ExceptionsPlugin(config),
    getSsecPlugin(config)
  ];
}).s("AmazonS3", "PutObject", {}).n("S3Client", "PutObjectCommand").f(PutObjectRequestFilterSensitiveLog, PutObjectOutputFilterSensitiveLog).ser(se_PutObjectCommand).de(de_PutObjectCommand).build() {
};

// lambda/lambda.ts
var import_node_fetch = __toESM(require_browser());
var s3Client = new S3Client({});
var BUCKET = process.env.BUCKET_NAME;
var BASE = process.env.BASE_URL;
var handler = async () => {
  const topRes = await (0, import_node_fetch.default)(`${BASE}service-reference.json`);
  const top = await topRes.json();
  const entries = [];
  for (const svc of Object.values(top.services)) {
    const url = new URL(svc.jsonUrl, BASE).href;
    const data = await (await (0, import_node_fetch.default)(url)).json();
    for (const [action, meta] of Object.entries(data.actions)) {
      const annotations = Array.isArray(meta.annotations) ? [...meta.annotations] : [];
      if (typeof meta.accessLevel === "string" && meta.accessLevel.toLowerCase() === "write") {
        if (!annotations.some((a2) => a2.toLowerCase().startsWith("iswrite"))) {
          annotations.push("IsWrite: true");
        }
      }
      entries.push({
        service: svc.serviceName,
        action,
        description: meta.description,
        annotations,
        conditionKeys: meta.conditionKeys || [],
        resourceTypes: meta.resourceTypes ? Object.keys(meta.resourceTypes) : []
      });
    }
  }
  await s3Client.send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: "aws-actions.json",
    Body: JSON.stringify(entries),
    ContentType: "application/json",
    CacheControl: "max-age=0"
  }));
};
