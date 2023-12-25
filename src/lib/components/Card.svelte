<script>
    export let title;
    export let link;
    export let discription;
    export let CTF = "notalink";
</script>

<style>
    #main {
        width: 400px;
        padding: 2rem;
        border-radius: 25px;
        background-color: lightgray;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: left;
    }
    #main:hover {
        box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
        transition: 0.1s;
    }
    * {
        margin: .5rem;
    }
</style>

<a href={link}>
    <div id="main">
        <h3>
            {title}
        </h3>
        {#if CTF !== "notalink"}
            <h4>{CTF}</h4>
        {/if}
        <p>
            {discription}
        </p>
    </div>
</a>
    