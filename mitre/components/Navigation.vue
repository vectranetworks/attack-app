<template>
  <q-drawer
    show-if-above
    v-model="leftDrawerOpen"
    class="print-hidden"
    side="left"
    bordered
  >
    <q-scroll-area class="fit">
      <q-list padding>
        <!-- Menu Item 1 -->
        <q-item clickable v-ripple to="/">
          <q-item-section avatar>
            <q-icon color="grey" name="groups" />
          </q-item-section>
          <q-item-section>
            <q-item-label>Threat Groups</q-item-label>
          </q-item-section>
        </q-item>
        <!-- Menu Item 2 -->
        <q-item clickable v-ripple to="/software">
          <q-item-section avatar>
            <q-icon color="grey" name="handyman" />
          </q-item-section>
          <q-item-section>
            <q-item-label>Malware & Tools</q-item-label>
          </q-item-section>
        </q-item>
        <q-item clickable v-ripple to="/tnumlookup">
          <q-item-section avatar>
            <q-icon color="grey" name="warning" />
          </q-item-section>
          <q-item-section>
            <q-item-label>T-number Lookup</q-item-label>
          </q-item-section>
        </q-item>
      </q-list>
    </q-scroll-area>
  </q-drawer>
</template>

<script setup>
defineProps(["leftDrawerOpen"]);
</script>
