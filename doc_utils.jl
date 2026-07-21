"""
Helper module to read Doxygen documentation metadata from libssh_jll.

This is used by the bindings and documentation generators.
"""
module DocUtils

import XML
import libssh_jll


"""
Get the element children of a node. Note that we can't rely on the positions of
elements because XML.jl also returns the whitespace between them as text nodes.
"""
function _elements(node)
    children = XML.children(node)
    if isnothing(children)
        return XML.Node[]
    end

    return filter(c -> XML.nodetype(c) == XML.Element, children)
end

"""
Find the first child element of `node` with the given tag, or `nothing`.
"""
function _find_element(node, tag::String)
    idx = findfirst(c -> XML.tag(c) == tag, _elements(node))
    return isnothing(idx) ? nothing : _elements(node)[idx]
end

"""
Read the function info from a Doxygen tag file into a dict.

In particular, the anchor file and the anchor itself.
"""
function read_tags()
    doc = read(libssh_jll.doxygen_tags, XML.Node)

    tagfile = _find_element(doc, "tagfile")
    if isnothing(tagfile)
        error("Couldn't find a <tagfile> element in $(libssh_jll.doxygen_tags)")
    end

    tags = Dict{Symbol, Any}()
    for compound in _elements(tagfile)
        attrs = XML.attributes(compound)
        if isnothing(attrs) || get(attrs, "kind", "") != "group"
            continue
        end

        for member in _elements(compound)
            member_attrs = XML.attributes(member)
            if XML.tag(member) != "member" || isnothing(member_attrs) ||
                get(member_attrs, "kind", "") != "function"
                continue
            end

            name = _find_element(member, "name")
            anchorfile = _find_element(member, "anchorfile")
            anchor = _find_element(member, "anchor")
            if any(isnothing, (name, anchorfile, anchor))
                continue
            end

            tags[Symbol(XML.simplevalue(name))] = (XML.simplevalue(anchorfile),
                                                   XML.simplevalue(anchor))
        end
    end

    if isempty(tags)
        error("No function tags found in $(libssh_jll.doxygen_tags), the tag file format may have changed")
    end

    return tags
end

function get_url(name::Symbol, tags)
    anchorfile, anchor = tags[name]
    return "https://api.libssh.org/stable/$(anchorfile)#$(anchor)"
end

end
