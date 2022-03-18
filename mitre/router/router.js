// Each Route is a link to a .vue file that will used where <router-view /> is in App.vue
const routes = [
  {
    path: "/",
    name: "Global State",
    component: Vue.defineAsyncComponent(() =>
      loadModule("views/Groups.vue", options)
    ),
  },
  {
    path: "/test",
    name: "Local State",
    component: Vue.defineAsyncComponent(() =>
      loadModule("views/Test2.vue", options)
    ),
  },
  {
    path: "/software",
    name: "Software/Malware",
    component: Vue.defineAsyncComponent(() =>
      loadModule("views/Software.vue", options)
    ),
  },
  {
    path: "/tnumlookup",
    name: "T-number Lookup",
    component: Vue.defineAsyncComponent(() =>
      loadModule("views/Tnumlookup.vue", options)
    ),
  },
];

// Define a new Router using VueRouter and assign the routes to it.
const router = VueRouter.createRouter({
  history: VueRouter.createWebHashHistory(),
  routes,
});

app.use(router);
