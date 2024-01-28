<script lang="ts">
    // @ts-ignore
    import init, { parse, vulnerabilities } from 'redos-wasm';
	import { onMount } from 'svelte';

    let hasBeenEnabled = false;

    onMount(() => {
        init().then(() => hasBeenEnabled = true);
    })

    let regex = "";
    let value = "";
    let vulns = "";

    $: if (hasBeenEnabled) {
        value = parse(regex)
        vulns = vulnerabilities(regex)
    }
</script>

<input bind:value={regex} />

<pre>
    {value}
</pre>

<pre>
    {vulns}
</pre>
