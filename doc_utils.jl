"""
Helper module to read Doxygen documentation metadata from libssh_jll.

This is used by the bindings and documentation generators.
"""
module DocUtils

import XML
import libssh_jll


"""
Read the function info from a Doxygen tag file into a dict.

In particular, the anchor file and the anchor itself.
"""
function read_tags()
    doc = read(libssh_jll.doxygen_tags, XML.Node)

    tags = Dict{Symbol, Any}()
    main_element = XML.children(doc)[2]
    for compound in XML.children(main_element)
        if compound["kind"] == "group"
            for child in filter(!isnothing, XML.children(compound))
                attrs = XML.attributes(child)
                if !isnothing(attrs) && get(attrs, "kind", "") == "function"
                    func_children = XML.children(child)
                    name = XML.simplevalue(func_children[2])
                    anchorfile = XML.simplevalue(func_children[3])
                    anchor = XML.simplevalue(func_children[4])

                    tags[Symbol(name)] = (anchorfile, anchor)
                end
            end
        end
    end

    return tags
end

function get_url(name::Symbol, tags)
    anchorfile, anchor = tags[name]
    return "https://api.libssh.org/stable/$(anchorfile)#$(anchor)"
end

end
