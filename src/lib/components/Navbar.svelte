<style>
  nav.navbar {
position: fixed;
display: inline;
width: 100%;
background-color: #857f7fdd;
color: rgb(0, 0, 0);
top: 0;
z-index: 100;
}

#home {
  float: left;
}

.menutoggle {
display: none;
}

.menucontainer {
display: none;
}

.navbar > ul {
list-style: none;
display: inline;
padding-right: 1rem;
}

.navbar > ul > li {
display: inline;
float: right;
padding: 1rem;
font-size: large;
}

.navbar > ul > li > a {
display: block;
padding: 1rem;
}

.navbar > ul > li:hover {
color: rgb(0, 0, 0);
text-decoration: underline;
}


.menubutton,
.menubutton::before,
.menubutton::after {
display: block;
background-color: #ffffff;
position: absolute;
height: 4px;
width: 30px;
transition: transform 400ms cubic-bezier(0.23, 1, 0.32, 1);
border-radius: 2px;
}

.menubutton::before {
content: "";
margin-top: -8px;
}

.menubutton::after {
content: "";
margin-top: 8px;
}

.menutoggle:checked + .menucontainer .menubutton::before {
margin-top: 0px;
transform: rotate(405deg);
}

.menutoggle:checked + .menucontainer .menubutton {
background: rgba(0, 0, 0, 0);
}

.menutoggle:checked + .menucontainer .menubutton::after {
margin-top: 0px;
transform: rotate(-405deg);
}

@media (max-width: 840px) {
nav.navbar {
  display: flex;
  flex-direction: row-reverse;
  align-items: center;
  justify-content: left;
  height: 48px;
}

.navbar > ul {
  display: flex;
  position: absolute;
  flex-direction: column-reverse;
  width: 100%;
  background-color: gray;
  margin: 0;
  align-items: center;
  top: 48px;
}

.navbar > ul > li {
  display: flex;
  justify-content: center;
  color: rgb(0, 0, 0);
}

.navbar > ul > li > a {
  display: flex;
  justify-content: center;
}

.menucontainer {
  display: flex;
  height: 100%;
  width: 30px;
  margin: 1rem;
  cursor: pointer;
  flex-direction: column-reverse;
  justify-content: center;
  align-items: center;
}

.navbar > ul > li:hover {
  color: rgb(10, 10, 10)  }

.menutoggle ~ ul > li {
  height: 0;
  margin: 0;
  padding: 0;
  border: 0;
  transition: height 400ms cubic-bezier(0.23, 1, 0.32, 1);
}

.menutoggle ~ ul > li > a {
  display: none;
}

.menutoggle:checked ~ ul > li {
  height: 5em;
  padding: 1em;
  transition: height 400ms cubic-bezier(0.23, 1, 0.32, 1);
}

.menutoggle:checked ~ ul > li > a {
  display: block;
}

}

</style>

<nav class='navbar'>
  <input
    class='menutoggle'
    id="menu-toggle"
    type="checkbox"
  />
  <label class='menucontainer' for="menu-toggle">
    <div class='menubutton'></div>
  </label>
  <ul>
    <li>
      <a href="/projects">Projects</a>
    </li>
    <li>
      <a href="/research">Research</a>
    </li>
    <li>
      <a href="/ctfs">CTFs</a>
    </li>
    <li>
      <a href="/about">About</a>
    </li>
    <li id="home">
      <a href="/" >Home</a>
    </li>
  </ul>
</nav>