<template>
  <div>
    <h1>Error Occured</h1>
    <p>Error has occured internally while processing the request.
      <router-link :to="{name: 'main'}">
        Retry
      </router-link>
    </p>
  </div>
</template>

<script>
export default {
  name: "GeneralError"
}
</script>