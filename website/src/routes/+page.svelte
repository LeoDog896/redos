<script lang="ts">
    // @ts-ignore
    import init, { parse } from 'redos-wasm';
	import { onMount } from 'svelte';

    let hasBeenEnabled = false;

    onMount(() => {
        init().then(() => hasBeenEnabled = true);
    })

    let regex = "";
    let value = "";

    $: if (hasBeenEnabled) {
        value = parse(regex)
    }
</script>

<input bind:value={regex} />

<pre>
    {value}
</pre>
