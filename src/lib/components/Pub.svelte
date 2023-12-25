
<script>
    export let title;
    export let authors;
    export let place;
    export let year;
    export let link;
</script>

<style>
    a {
        color: blue
    }
</style>

<li>
    <h3>{title}</h3>
    <p>{authors}</p>
    <p>{place} {year} <a href={link}>Link</a></p>
</li>
