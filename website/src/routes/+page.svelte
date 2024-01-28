<script lang="ts">
	// @ts-ignore
	import init, { parse, ir, vulnerabilities } from 'redos-wasm';
	import { onMount } from 'svelte';

	let hasBeenEnabled = false;

	onMount(() => {
		init().then(() => (hasBeenEnabled = true));
	});

	let regex = '';
	let ast = '';
	let irValue = '';
	let vulns = '';

	$: if (hasBeenEnabled) {
		ast = parse(regex);
		irValue = ir(regex);
		vulns = vulnerabilities(regex);
	}
</script>

<main>
    <input bind:value={regex} placeholder="Enter Regex" />

    <div class="output">
        <div class="subContainer">
            <h1>AST</h1>
            <pre>{ast}</pre>
        </div>
        <div class="subContainer">
            <h1>IR</h1>
            <pre>{irValue}</pre>
        </div>
        <div class="subContainer">
            <h1>Vulnerabilities</h1>
            <pre>{vulns}</pre>
        </div>
    </div>
</main>

<style lang="scss">
    main {
        display: flex;
        flex-direction: column;
        align-items: center;
        width: calc(100% - 4rem);
        height: calc(100% - 4rem);
        margin: 2rem;
    }

    input {
        width: 100%;
        height: 2rem;
        font-size: 1.5rem;
        padding: 0.5rem;
        background-color: var(--backgroundIsh);
        border: none;
        outline: none;
        border-bottom: 2px solid var(--primary);
        color: var(--primary);
        transition: border-bottom 0.2s ease-in-out;
        text-align: center;

        &:active, &:focus {
            border-bottom: 6px solid var(--primary);
        }
    }

    .output {
        display: flex;
        flex-direction: row;
        width: 100%;
        gap: 1rem;
        justify-content: space-between;
    }

    .subContainer {
        margin-top: 2rem;
        width: 30%;
        height: 100%;
        padding: 1rem;
        background-color: var(--backgroundIsh);
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.5rem;

        h1 {
            font-size: 2rem;
            text-align: center;
            margin: 0;
            padding-bottom: 0.5rem;
            border-bottom: 2px dashed var(--secondary);
        }
    }
</style>
