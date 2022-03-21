<template>
  <q-layout view="hHh LpR fFf">
    <q-header bordered class="bg-primary text-white print-hidden">
      <q-toolbar>
        <q-btn dense flat round icon="menu" @click="toggleLeftDrawer" />

        <q-toolbar-title class="print-hidden">
          <q-avatar>
            <img src="https://cdn.quasar.dev/logo-v2/svg/logo-mono-white.svg" />
          </q-avatar>
          MITRE ATT&CK Explorer
        </q-toolbar-title>
      </q-toolbar>
    </q-header>

    <Navigation :leftDrawerOpen="leftDrawerOpen" />

    <q-page-container>
      <div style="padding: 16px">
        <router-view />
      </div>
    </q-page-container>
  </q-layout>
</template>

<script>
import { ref } from "vue";
import Navigation from "./components/Navigation.vue";

export default {
  setup() {
    const leftDrawerOpen = ref(true);
    return {
      leftDrawerOpen,
      toggleLeftDrawer() {
        leftDrawerOpen.value = !leftDrawerOpen.value;
      },
    };
  },
  components: { Navigation },
};
</script>
