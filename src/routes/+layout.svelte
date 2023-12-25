<script>
    import Navbar from "$lib/components/Navbar.svelte"
</script>

<style>
main {
    position: absolute;
    top: 85px;
    width: 100%;
    height: 100%;
}
</style>


<main>
    <Navbar/>
    <slot></slot>
</main>
