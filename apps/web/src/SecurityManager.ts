/*
Copyright 2024 New Vector Ltd.
Copyright 2019, 2020 The Matrix.org Foundation C.I.C.

SPDX-License-Identifier: AGPL-3.0-only OR GPL-3.0-only OR LicenseRef-Element-Commercial
Please see LICENSE files in the repository root for full details.
*/

import { lazy } from "react";
import { type SecretStorage } from "matrix-js-sdk/src/matrix";
import { deriveRecoveryKeyFromPassphrase, decodeRecoveryKey, type CryptoCallbacks } from "matrix-js-sdk/src/crypto-api";
import { logger as rootLogger } from "matrix-js-sdk/src/logger";

import Modal from "./Modal";
import { MatrixClientPeg } from "./MatrixClientPeg";
import { _t } from "./languageHandler";
import AccessSecretStorageDialog, {
    type KeyParams,
} from "./components/views/dialogs/security/AccessSecretStorageDialog";
import { ModuleRunner } from "./modules/ModuleRunner";
import InteractiveAuthDialog from "./components/views/dialogs/InteractiveAuthDialog";

// This stores the secret storage private keys in memory for the JS SDK. This is
// only meant to act as a cache to avoid prompting the user multiple times
// during the same single operation. Use `accessSecretStorage` below to scope a
// single secret storage operation, as it will clear the cached keys once the
// operation ends.
let secretStorageKeys: Record<string, Uint8Array<ArrayBuffer>> = {};
let secretStorageKeyInfo: Record<string, SecretStorage.SecretStorageKeyDescription> = {};
let secretStorageBeingAccessed = false;

const logger = rootLogger.getChild("SecurityManager:");

/**
 * This can be used by other components to check if secret storage access is in
 * progress, so that we can e.g. avoid intermittently showing toasts during
 * secret storage setup.
 *
 * @returns {bool}
 */
export function isSecretStorageBeingAccessed(): boolean {
    return secretStorageBeingAccessed;
}

export class AccessCancelledError extends Error {
    public constructor() {
        super("Secret storage access canceled");
    }
}

export function makeInputToKey(
    keyInfo: SecretStorage.SecretStorageKeyDescription,
): (keyParams: KeyParams) => Promise<Uint8Array<ArrayBuffer>> {
    return async ({ passphrase, recoveryKey }): Promise<Uint8Array<ArrayBuffer>> => {
        if (passphrase) {
            return deriveRecoveryKeyFromPassphrase(passphrase, keyInfo.passphrase.salt, keyInfo.passphrase.iterations);
        } else if (recoveryKey) {
            return decodeRecoveryKey(recoveryKey);
        }
        throw new Error("Invalid input, passphrase or recoveryKey need to be provided");
    };
}

/**
 * Preload a 4S key so the next {@link accessSecretStorage} does not prompt.
 * Used when the recovery-key form is shown inline (Complete Security / verify session).
 */
let forcedSecretStorageKey: Uint8Array<ArrayBuffer> | null = null;

export function setForcedSecretStorageKey(key: Uint8Array<ArrayBuffer> | null): void {
    forcedSecretStorageKey = key;
}

async function getSecretStorageKey(
    {
        keys: keyInfos,
    }: {
        keys: Record<string, SecretStorage.SecretStorageKeyDescription>;
    },
    secretName: string,
): Promise<[string, Uint8Array<ArrayBuffer>]> {
    const cli = MatrixClientPeg.safeGet();
    const defaultKeyId = await cli.secretStorage.getDefaultKeyId();

    let keyId: string;
    // If the defaultKey is useful, use that
    if (defaultKeyId && keyInfos[defaultKeyId]) {
        keyId = defaultKeyId;
    } else {
        // Fall back to a heuristic of using the
        // only available key, if only one key is set
        const usefulKeys = Object.keys(keyInfos);
        if (usefulKeys.length > 1) {
            throw new Error("Multiple storage key requests not implemented");
        }
        keyId = usefulKeys[0];
    }
    const keyInfo = keyInfos[keyId];
    logger.debug(
        `getSecretStorageKey: request for 4S keys [${Object.keys(keyInfos)}] for secret \`${secretName}\`: looking for key ${keyId}`,
    );

    // Check the in-memory cache
    if (secretStorageBeingAccessed && secretStorageKeys[keyId]) {
        logger.debug(`getSecretStorageKey: returning key ${keyId} from cache`);
        return [keyId, secretStorageKeys[keyId]];
    }

    if (forcedSecretStorageKey) {
        logger.debug(`getSecretStorageKey: using preloaded recovery key for ${keyId}`);
        cacheSecretStorageKey(keyId, keyInfo, forcedSecretStorageKey);
        return [keyId, forcedSecretStorageKey];
    }

    const keyFromCustomisations = ModuleRunner.instance.extensions.cryptoSetup.getSecretStorageKey();
    if (keyFromCustomisations) {
        logger.debug("getSecretStorageKey: Using secret storage key from CryptoSetupExtension");
        cacheSecretStorageKey(keyId, keyInfo, keyFromCustomisations);
        return [keyId, keyFromCustomisations];
    }

    // Prompt for whichever key can decrypt the secret — including when
    // m.secret_storage.default_key is missing or points elsewhere. Throwing
    // here made "Use recovery key" a silent no-op (the button is shown as soon
    // as *any* 4S key holds m.cross_signing.master).
    if (keyId !== defaultKeyId) {
        logger.debug(
            `getSecretStorageKey: key ${keyId} is not the default (${defaultKeyId}): still prompting user`,
        );
    }

    logger.debug(`getSecretStorageKey: prompting user for key ${keyId}`);
    const inputToKey = makeInputToKey(keyInfo);
    // Priority so the prompt is above static dialogs (verify-session toast).
    const { finished } = Modal.createDialog(
        AccessSecretStorageDialog,
        /* props= */
        {
            keyInfo,
            checkPrivateKey: async (input: KeyParams): Promise<boolean> => {
                const key = await inputToKey(input);
                return MatrixClientPeg.safeGet().secretStorage.checkKey(key, keyInfo);
            },
        },
        "mx_Dialog_recoveryKey",
        /* isPriorityModal = */ true,
    );
    const [keyParams] = await finished;
    if (!keyParams) {
        throw new AccessCancelledError();
    }
    logger.debug(`getSecretStorageKey: got key ${keyId} from user`);
    const key = await inputToKey(keyParams);

    // Save to cache to avoid future prompts in the current session
    cacheSecretStorageKey(keyId, keyInfo, key);

    return [keyId, key];
}

function cacheSecretStorageKey(
    keyId: string,
    keyInfo: SecretStorage.SecretStorageKeyDescription,
    key: Uint8Array<ArrayBuffer>,
): void {
    if (secretStorageBeingAccessed) {
        logger.debug(`Caching 4S key ${keyId}`);
        secretStorageKeys[keyId] = key;
        secretStorageKeyInfo[keyId] = keyInfo;
    }
}

export const crossSigningCallbacks: CryptoCallbacks = {
    getSecretStorageKey,
    cacheSecretStorageKey,
};

/**
 * Carry out an operation that may require multiple accesses to secret storage, caching the key.
 *
 * Use this helper to wrap an operation that may require multiple accesses to secret storage; the user will be prompted
 * to enter the 4S key or passphrase on the first access, and the key will be cached for the rest of the operation.
 *
 * @param func - The operation to be wrapped.
 */
export async function withSecretStorageKeyCache<T>(func: () => Promise<T>): Promise<T> {
    logger.debug("enabling 4S key cache");
    secretStorageBeingAccessed = true;
    try {
        return await func();
    } finally {
        // Clear secret storage key cache now that work is complete
        logger.debug("disabling 4S key cache");
        secretStorageBeingAccessed = false;
        secretStorageKeys = {};
        secretStorageKeyInfo = {};
    }
}

export interface AccessSecretStorageOpts {
    /**
     * Reset secret storage even if it's already set up.
     * @deprecated send the user to the Encryption settings tab to reset secret storage
     */
    forceReset?: boolean;
}

/**
 * This helper should be used whenever you need to access secret storage. It
 * ensures that secret storage (and also cross-signing since they each depend on
 * each other in a cycle of sorts) have been bootstrapped before running the
 * provided function.
 *
 * Bootstrapping secret storage may take one of these paths:
 * 1. (Only if `opts.forceReset` is set) create secret storage from a passphrase
 *    and store cross-signing keys in secret storage.
 * 2. Access existing secret storage by requesting passphrase and accessing
 *    cross-signing keys as needed.
 * 3. All keys are loaded and there's nothing to do.
 *
 * Additionally, the secret storage keys are cached during the scope of this function
 * to ensure the user is prompted only once for their secret storage
 * passphrase. The cache is then cleared once the provided function completes.
 *
 * Throws an error if secret storage is not set up (and `opts.forceReset` is not set)
 *
 * @param {Function} [func] An operation to perform once secret storage has been
 * bootstrapped. Optional.
 * @param [opts] The options to use when accessing secret storage.
 */
export async function accessSecretStorage(
    func = async (): Promise<void> => {},
    opts: AccessSecretStorageOpts = {},
): Promise<void> {
    await withSecretStorageKeyCache(() => doAccessSecretStorage(func, opts));
}

/**
 * If `m.secret_storage.default_key` is missing but a 4S key already encrypts
 * `m.cross_signing.master`, point the default at that key. Otherwise
 * `hasKey()` is false, "Use recovery key" accepts a valid key, then
 * `accessSecretStorage` aborts with "Secret storage has not been created yet."
 */
async function repairDefaultSecretStorageKey(): Promise<void> {
    const cli = MatrixClientPeg.safeGet();
    const stored = await cli.secretStorage.isStored("m.cross_signing.master");
    if (!stored || typeof stored !== "object") {
        return;
    }
    const keyIds = Object.keys(stored);
    if (keyIds.length === 0) {
        return;
    }
    const keyId = keyIds[0];
    logger.debug(
        `accessSecretStorage: no default 4S key; setting default to ${keyId} (holds m.cross_signing.master)`,
    );
    if (typeof cli.secretStorage.setDefaultKeyId === "function") {
        await cli.secretStorage.setDefaultKeyId(keyId);
    }
}

/** Helper for {@link #accessSecretStorage} */
async function doAccessSecretStorage(func: () => Promise<void>, opts: AccessSecretStorageOpts): Promise<void> {
    try {
        const cli = MatrixClientPeg.safeGet();
        const crypto = cli.getCrypto();
        if (!crypto) {
            throw new Error("End-to-end encryption is disabled - unable to access secret storage.");
        }

        if (opts.forceReset) {
            logger.debug("accessSecretStorage: resetting 4S");
            // This dialog calls bootstrap itself after guiding the user through
            // passphrase creation.
            const { finished } = Modal.createDialog(
                lazy(() => import("./async-components/views/dialogs/security/CreateSecretStorageDialog")),
                opts,
                undefined,
                /* priority = */ false,
                /* static = */ true,
            );
            const [confirmed] = await finished;
            if (!confirmed) {
                throw new Error("Secret storage creation canceled");
            }
        } else {
            if (!(await cli.secretStorage.hasKey())) {
                await repairDefaultSecretStorageKey();
            }
            if (!(await cli.secretStorage.hasKey()) && !forcedSecretStorageKey) {
                logger.debug("accessSecretStorage: no 4S key configured");
                throw new Error("Secret storage has not been created yet.");
            }

            logger.debug("accessSecretStorage: bootstrapCrossSigning");
            await crypto.bootstrapCrossSigning({
                authUploadDeviceSigningKeys: async (makeRequest): Promise<void> => {
                    logger.debug("accessSecretStorage: performing UIA to upload cross-signing keys");
                    const { finished } = Modal.createDialog(
                        InteractiveAuthDialog,
                        {
                            title: _t("encryption|bootstrap_title"),
                            matrixClient: cli,
                            makeRequest,
                        },
                        undefined,
                        /* isPriorityModal = */ true,
                    );
                    const [confirmed] = await finished;
                    if (!confirmed) {
                        throw new Error("Cross-signing key upload auth canceled");
                    }
                    logger.debug("accessSecretStorage: Cross-signing key upload successful");
                },
            });
            logger.debug("accessSecretStorage: bootstrapSecretStorage");
            await crypto.bootstrapSecretStorage({});
        }

        logger.debug("accessSecretStorage: 4S now ready");
        // `return await` needed here to ensure `finally` block runs after the
        // inner operation completes.
        await func();
        logger.debug("accessSecretStorage: operation complete");
    } catch (e) {
        ModuleRunner.instance.extensions.cryptoSetup.catchAccessSecretStorageError(e as Error);
        logger.error("accessSecretStorage: error during operation", e);
        // Re-throw so that higher level logic can abort as needed
        throw e;
    }
}
