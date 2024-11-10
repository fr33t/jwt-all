<script setup lang="ts">
import { ref } from 'vue'
const algs = ref(["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"])
const selected_alg = ref("HS256")
const sjwt = ref("")
const tjwt = ref("")
const header = ref("")
const payload = ref("")
const verify_signature = ref("")

const decodeJwt = () => {
    let jwt = sjwt.value.trim().split(".")
    if (jwt.length > 3) {
        alert("Invalid JWT format!")
        return
    }
    console.log(jwt)
    if (jwt.length >= 1 && jwt[0]) {
        let h = JSON.stringify(JSON.parse(atob(jwt[0])), null, 2)
        header.value = h
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

const encodeJwt = () => {
    let t = ""
    try {
        let h = header.value
        if (h) {
            let header_b64 = btoa(JSON.stringify(JSON.parse(h)))
            t += header_b64
        }

        let p = payload.value
        if (p) {
            let payload_b64 = btoa(JSON.stringify(JSON.parse(p)))
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

</script>
<template>
    <div class="d-flex justify-center">
        <div class="d-flex flex-column w-75">

            <div class="d-flex justify-space-between mt-10">

                <v-btn @click="decodeJwt" variant="text">
                    <h1>JWT-ALL</h1>
                </v-btn>

                <p>Click me to decode jwt!</p>

                <div class="w-33"></div>

                <v-select width="100px" label="Alg" :model-value="selected_alg" :items=algs
                    variant="outlined"></v-select>
            </div>

            <div>
                <v-textarea rows="5" label="S-JWT" variant="outlined" no-resize v-model="sjwt"></v-textarea>
                <div class="d-flex">
                    <v-textarea rows="10" class="mr-2" label="Header" variant="outlined" no-resize v-model="header"
                        @blur="encodeJwt"></v-textarea>
                    <v-textarea rows="10" class="mr-2" label="Payload" variant="outlined" no-resize v-model="payload"
                        @blur="encodeJwt"></v-textarea>
                    <v-textarea rows="10" label="Verify Signature" variant="outlined" no-resize></v-textarea>
                </div>
            </div>


            <v-textarea rows="5" label="T-JWT" variant="outlined" no-resize v-model="tjwt"></v-textarea>


        </div>


    </div>
</template>
