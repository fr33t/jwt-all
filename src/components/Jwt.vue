<script setup lang="ts">
import { onMounted, ref } from 'vue'
const algs = ref(["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"])
const selected_alg = ref("HS256")
const sjwt = ref("")
const tjwt = ref("")
const header = ref("")
const payload = ref("")
const verify_signature = ref("")
const signature_type = ref("")

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

const encodeJwt = () => {
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
        if (s) {
            t += "." + s
        }

        tjwt.value = t
    } catch (e) {
        alert("Invalid Modified JWT format!")
    }
}

const clearJwt = () => {
    tjwt.value = ""
    header.value = ""
    payload.value = ""
    signature_type.value = ""
}

onMounted(() => {
    sjwt.value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.7aB3f5gF-3B44E8aWo063ryJYjOmZEvjkMbSXRfyos4"
    decodeJwt()
    encodeJwt()
})
</script>
<template>
    <div class="d-flex justify-center">
        <div class="d-flex flex-column w-75">

            <div class="d-flex justify-space-between mt-10">

                <v-btn @mousedown="(event: MouseEvent) => {
                    console.log(event.button)
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


        </div>


    </div>
</template>
