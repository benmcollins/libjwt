/**

Doxygen Awesome
https://github.com/jothepro/doxygen-awesome-css

MIT License

Copyright (c) 2022 - 2023 jothepro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

class DoxygenAwesomeParagraphLink {
    static title = "Permanent Link"
    static init() {
        $(function() {
            $(document).ready(function() {
                document.querySelectorAll(".contents a.anchor[id], .contents .groupheader > a[id]").forEach((node) => {
                    let anchorlink = document.createElement("a")
                    anchorlink.setAttribute("href", `#${node.getAttribute("id")}`)
                    anchorlink.setAttribute("title", DoxygenAwesomeParagraphLink.title)
                    anchorlink.classList.add("anchorlink")
                    node.classList.add("anchor")
                    anchorlink.innerHTML = DoxygenAwesomeParagraphIcon.icon
                    node.parentElement.appendChild(anchorlink)
                })
            })
        })
    }
}
