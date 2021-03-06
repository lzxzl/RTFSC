import os
import sys
import platform
import logging
from collections import OrderedDict
from typing import Optional, List

import archinfo
from archinfo.arch_soot import ArchSoot

from .address_translator import AT
from .utils import ALIGN_UP, key_bisect_floor_key, key_bisect_insort_right

__all__ = ('Loader',)

l = logging.getLogger(name=__name__)


class Loader:
    """
    The loader loads all the objects and exports an abstraction of the memory of the process. What you see here is an
    address space with loaded and rebased binaries.
    Loader 加载所有的对象并导出一个进程内存的抽象。在此处所看到的是一个含有已加载和重定位的二进制文件的地址空间。

    :param main_binary:         The path to the main binary you're loading, or a file-like object with the binary
                                in it. 要加载的主二进制文件的路径，或者包含二进制文件的类文件对象

    The following parameters are optional. 下面是可选参数

    :param auto_load_libs:      Whether to automatically load shared libraries that loaded objects depend on. 
								是否自动加载已加载对象所依赖的共享库
	
    :param load_debug_info:     Whether to automatically parse DWARF data and search for debug symbol files.
								是否自动解析DWARF数据并搜索调试符号文件
	
    :param concrete_target:     Whether to instantiate a concrete target for a concrete execution of the process.
                                if this is the case we will need to instantiate a SimConcreteEngine that wraps the
                                ConcreteTarget provided by the user.
								是否为进程的具体执行实例化具体目标。如果是这种情况，我们将需要实例化一个包含用户提供的ConcreteTarget的SimConcreteEngine
								
    :param force_load_libs:     A list of libraries to load regardless of if they're required by a loaded object.
								要强制加载的库列表，而不管加载的对象是否需要它们
	
    :param skip_libs:           A list of libraries to never load, even if they're required by a loaded object.
								绝不加载的库列表，即使加载的对象需要它们
	
    :param main_opts:           A dictionary of options to be used loading the main binary.
								加载主二进制文件时的选项字典
	
    :param lib_opts:            A dictionary mapping library names to the dictionaries of options to be used when
                                loading them.
								加载库时的选项字典，该字典映射库名字到加载它们时所使用的选项字典
								
    :param ld_path:             A list of paths in which we can search for shared libraries.
						        可以搜索共享库的路径列表
	
    :param use_system_libs:     Whether or not to search the system load path for requested libraries. Default True.
								是否搜索所请求库的系统加载路径，默认为True
	
    :param ignore_import_version_numbers:
                                Whether libraries with different version numbers in the filename will be considered
                                equivalent, for example libc.so.6 and libc.so.0
								文件名中具有不同版本号的库是否会被视为等效，例如libc.so.6和libc.so.0是否会被视为等效
								
    :param case_insensitive:    If this is set to True, filesystem loads will be done case-insensitively regardless of
                                the case-sensitivity of the underlying filesystem.
								如果这个参数设置为True，无论底层文件系统是否区分大小写，文件系统加载都将不区分大小写   底层文件系统？？
								
    :param rebase_granularity:  The alignment to use for rebasing shared objects
								用于重定位共享对象的对齐方式
	
    :param except_missing_libs: Throw an exception when a shared library can't be found.
								当无法找到共享库时抛出异常
	
    :param aslr:                Load libraries in symbolic address space. Do not use this option.
								在符号地址空间中加载库。 不要使用此选项
	
    :param page_size:           The granularity with which data is mapped into memory. Set to 1 if you are working
                                in a non-paged environment.
								数据映射到内存的粒度，如果在非分页环境中工作，则设置为1
								
    :param preload_libs:        Similar to `force_load_libs` but will provide for symbol resolution, with precedence
                                over any dependencies.
								类似于 force_load_libs，但是会提供符号解析，优先于任何依赖项。
								
    :ivar memory:               The loaded, rebased, and relocated memory of the program. 程序的加载、重新定位和重定位的内存
    :vartype memory:            cle.memory.Clemory
	
    :ivar main_object:          The object representing the main binary (i.e., the executable). 代表主二进制文件的对象
	
    :ivar shared_objects:       A dictionary mapping loaded library names to the objects representing them. 映射加载库名字到它们所代表对象的一个字典
	
    :ivar all_objects:          A list containing representations of all the different objects loaded. 包含所有被加载对象的代表的列表
	
    :ivar requested_names:      A set containing the names of all the different shared libraries that were marked as a
                                dependency by somebody. 包含被某人标记为依赖项的所有不同共享库的名字的集合
								
    :ivar initial_load_objects: A list of all the objects that were loaded as a result of the initial load request.
								由于初始加载请求而加载的所有对象的列表     初始加载请求？？

    When reference is made to a dictionary of options, it requires a dictionary with zero or more of the following keys:
	当设置了选项字典时，即要设置main_opts或lib_opts参数时，字典里的key可以是下述中的0个或多个

    - backend :             "elf", "pe", "mach-o", "blob" : which loader backend to use  要使用的加载器后端
    - arch :                The archinfo.Arch object to use for the binary 针对二进制文件要使用的archinfo.Arch对象
    - base_addr :           The address to rebase the object at  指定基址
    - entry_point :         The entry point to use for the object  指定对象的入口点

    More keys are defined on a per-backend basis.
    """
    # _main_binary_path: str
    memory: Optional['Clemory']
    main_object: Optional['Backend']
    tls: Optional['ThreadManager']

    def __init__(self, main_binary, auto_load_libs=True, concrete_target = None,
                 force_load_libs=(), skip_libs=(),
                 main_opts=None, lib_opts=None, ld_path=(), use_system_libs=True,
                 ignore_import_version_numbers=True, case_insensitive=False, rebase_granularity=0x100000,
                 except_missing_libs=False, aslr=False, perform_relocations=True, load_debug_info=False,
                 page_size=0x1, preload_libs=(), arch=None):
        if hasattr(main_binary, 'seek') and hasattr(main_binary, 'read'): # 如果main_binary是一个流，设置_main_binary_stream
            self._main_binary_path = None
            self._main_binary_stream = main_binary
        else:
            self._main_binary_path = os.path.realpath(str(main_binary)) # 否者设置 _main_binary_path
            self._main_binary_stream = None

        # whether we are presently in the middle of a load cycle  我们目前是否处于加载周期的中间
        self._juggling = False

        # auto_load_libs doesn't make any sense if we have a concrete target. 如果有一个具体的目标，则 auto_load_libs 没有意义
        if concrete_target:
            auto_load_libs = False

        self._auto_load_libs = auto_load_libs
        self._load_debug_info = load_debug_info
        self._satisfied_deps = dict((x, False) for x in skip_libs)
        self._main_opts = {} if main_opts is None else main_opts
        self._lib_opts = {} if lib_opts is None else lib_opts
        self._custom_ld_path = [ld_path] if type(ld_path) is str else ld_path
        force_load_libs = [force_load_libs] if type(force_load_libs) is str else force_load_libs
        preload_libs = [preload_libs] if type(preload_libs) is str else preload_libs
        self._use_system_libs = use_system_libs
        self._ignore_import_version_numbers = ignore_import_version_numbers
        self._case_insensitive = case_insensitive
        self._rebase_granularity = rebase_granularity
        self._except_missing_libs = except_missing_libs
        self._relocated_objects = set()
        self._perform_relocations = perform_relocations

        # case insensitivity setup 大小写不敏感设置
        if sys.platform == 'win32': # TODO: a real check for case insensitive filesystems  如果系统平台是win32
            if self._main_binary_path: self._main_binary_path = self._main_binary_path.lower()
            force_load_libs = [x.lower() if type(x) is str else x for x in force_load_libs]
            for x in list(self._satisfied_deps): self._satisfied_deps[x.lower()] = self._satisfied_deps[x]
            for x in list(self._lib_opts): self._lib_opts[x.lower()] = self._lib_opts[x]
            self._custom_ld_path = [x.lower() for x in self._custom_ld_path]

        self.aslr = aslr
        self.page_size = page_size
        self.memory = None
        self.main_object = None
        self.tls = None
        self._kernel_object = None # type: Optional[KernelObject]
        self._extern_object = None # type: Optional[ExternObject]
        self.shared_objects = OrderedDict()
        self.all_objects = []  # type: List[Backend]
        self.requested_names = set()
        if arch is not None:
            self._main_opts.update({'arch': arch})
        self.preload_libs = []
		
		# 调用_internal_load进行内部加载所有对象，返回一个所加载对象的列表。
		# 传入的参数有 主二进制文件、预加载库、强制加载库。
		# 如果有其中一个对象不能正确加载，函数将退出
        self.initial_load_objects = self._internal_load(main_binary, *preload_libs, *force_load_libs, preloading=(main_binary, *preload_libs))

        # cache
        self._last_object = None

        if self._extern_object and self._extern_object._warned_data_import:
            l.warning('For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata')

    # Basic functions and properties

    def close(self):
        l.warning("You don't need to close the loader anymore :)")

    def __repr__(self):
        if self._main_binary_stream is None:
            return '<Loaded %s, maps [%#x:%#x]>' % (os.path.basename(self._main_binary_path), self.min_addr, self.max_addr)
        else:
            return '<Loaded from stream, maps [%#x:%#x]>' % (self.min_addr, self.max_addr)

    @property  # 这个装饰器把函数变成属性使用
    def max_addr(self):
        """
        The maximum address loaded as part of any loaded object (i.e., the whole address space).
		获取地址空间里最后一个对象的最大地址
        """
        return self.all_objects[-1].max_addr

    @property
    def min_addr(self):
        """
        The minimum address loaded as part of any loaded object (i.e., the whole address space).
        """
        return self.all_objects[0].min_addr

    @property
    def initializers(self):
        """
        Return a list of all the initializers that should be run before execution reaches the entry point, in the order
        they should be run.
        """
        return sum((x.initializers for x in self.all_objects), [])

    @property
    def finalizers(self):
        """
        Return a list of all the finalizers that should be run before the program exits.
        I'm not sure what order they should be run in.
        """
        return sum((x.finalizers for x in self.all_objects), [])

    @property
    def linux_loader_object(self):
        """
        If the linux dynamic loader is present in memory, return it
        """
        for obj in self.all_objects:
            if obj.provides is None:
                continue
            if self._is_linux_loader_name(obj.provides) is True:
                return obj
        return None

    @property
    def elfcore_object(self):
        """
        If a corefile was loaded, this returns the actual core object instead of the main binary
        """
        for obj in self.all_objects:
            if isinstance(obj, ELFCore):
                return obj
        return None

    @property
    def extern_object(self):
        """
        Return the extern object used to provide addresses to unresolved symbols and angr internals.

        Accessing this property will load this object into memory if it was not previously present.

        proposed model for how multiple extern objects should work:

            1) extern objects are a linked list. the one in loader._extern_object is the head of the list
            2) each round of explicit loads generates a new extern object if it has unresolved dependencies. this object
               has exactly the size necessary to hold all its exports.
            3) All requests for size are passed down the chain until they reach an object which has the space to service it
               or an object which has not yet been mapped. If all objects have been mapped and are full, a new extern object
               is mapped with a fixed size.
        """
        if self._extern_object is None:
            if self.main_object.arch.bits < 32:
                extern_size = 0x200
            elif self.main_object.arch.bits == 32:
                extern_size = 0x8000
            else:
                extern_size = 0x80000
            self._extern_object = ExternObject(self, map_size=extern_size)
            self._internal_load(self._extern_object)
        return self._extern_object

    @property
    def kernel_object(self) -> 'KernelObject':
        """
        Return the object used to provide addresses to syscalls.

        Accessing this property will load this object into memory if it was not previously present.
        """
        if self._kernel_object is None:
            self._kernel_object = KernelObject(self)
            self._map_object(self._kernel_object)
        return self._kernel_object

    @property
    def all_elf_objects(self):
        """
        Return a list of every object that was loaded from an ELF file.
        """
        return [o for o in self.all_objects if isinstance(o, MetaELF)]

    @property
    def all_pe_objects(self):
        """
        Return a list of every object that was loaded from an ELF file.
        """
        return [o for o in self.all_objects if isinstance(o, PE)]

    @property
    def missing_dependencies(self):
        """
        Return a set of every name that was requested as a shared object dependency but could not be loaded
        """
        return self.requested_names - set(k for k,v in self._satisfied_deps.items() if v is not False)

    @property
    def auto_load_libs(self):
        return self._auto_load_libs

    def describe_addr(self, addr):
        """
        Returns a textual description of what's in memory at the provided address
        """
        o = self.find_object_containing(addr)

        if o is None:
            return 'not part of a loaded object'

        options = []

        rva = AT.from_va(addr, o).to_rva()

        idx = o.symbols.bisect_key_right(rva) - 1
        while idx >= 0:
            sym = o.symbols[idx]
            if not sym.name or sym.is_import:
                idx -= 1
                continue
            options.append((sym.relative_addr, '%s+' % sym.name))
            break

        if isinstance(o, ELF):
            try:
                plt_addr, plt_name = max((a, n) for n, a in o._plt.items() if a <= rva)
            except ValueError:
                pass
            else:
                options.append((plt_addr, 'PLT.%s+' % plt_name))

        options.append((0, 'offset '))

        if o.provides:
            objname = o.provides
        elif o.binary:
            objname = os.path.basename(o.binary)
        elif self.main_object is o:
            objname = 'main binary'
        else:
            objname = 'object loaded from stream'

        best_offset, best_prefix = max(options, key=lambda v: v[0])
        return '%s%#x in %s (%#x)' % (best_prefix, rva - best_offset, objname, AT.from_va(addr, o).to_lva())

    # Search functions

    def find_object(self, spec, extra_objects=()):
        """
        If the given library specification has been loaded, return its object, otherwise return None.
		如果给定的库已经被加载，那么返回他的对象，否则返回None
        """
        if isinstance(spec, Backend): # 如果spec是Backend对象
            for obj in self.all_objects:
                if obj is spec:
                    return obj  # 如果spec是加载器加载的对象，则返回obj
            return None

        if self._case_insensitive: # 如果大小写不敏感
            spec = spec.lower() #  转为小写
        extra_idents = {}
        for obj in extra_objects:
            for ident in self._possible_idents(obj):
                extra_idents[ident] = obj

        for ident in self._possible_idents(spec):
            if ident in self._satisfied_deps:
                return self._satisfied_deps[ident]
            if ident in extra_idents:
                return extra_idents[ident]

        return None

    def find_object_containing(self, addr, membership_check=True):
        """
        Return the object that contains the given address, or None if the address is unmapped.

        :param int addr:    The address that should be contained in the object.
        :param bool membership_check:   Whether a membership check should be performed or not (True by default). This
                                        option can be set to False if you are certain that the target object does not
                                        have "holes".
        :return:            The object or None.
        """

        def _check_object_memory(obj_):
            if isinstance(obj_.memory, Clemory):
                if AT.from_va(addr, obj_).to_rva() in obj_.memory:
                    self._last_object = obj_
                    return obj_
                return None
            elif type(obj_.memory) is str:
                self._last_object = obj_
                return obj_
            else:
                raise CLEError('Unsupported memory type %s' % type(obj_.memory))

        # check the cache first
        if self._last_object is not None and \
                self._last_object.min_addr <= addr <= self._last_object.max_addr:
            if not membership_check: return self._last_object
            if not self._last_object.has_memory: return self._last_object
            o = _check_object_memory(self._last_object)
            if o: return o

        if addr > self.max_addr or addr < self.min_addr:
            return None

        obj = key_bisect_floor_key(self.all_objects, addr, keyfunc=lambda obj: obj.min_addr)
        if obj is None:
            return None
        if not obj.min_addr <= addr <= obj.max_addr:
            return None
        if not membership_check:
            self._last_object = obj
            return obj
        if not obj.has_memory:
            self._last_object = obj
            return obj
        return _check_object_memory(obj)

    def find_segment_containing(self, addr, skip_pseudo_objects=True):
        """
        Find the section object that the address belongs to.

        :param int addr: The address to test
        :param bool skip_pseudo_objects: Skip objects that CLE adds during loading.
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Segment
        """

        obj = self.find_object_containing(addr, membership_check=False)

        if obj is None:
            return None

        if skip_pseudo_objects and isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a section allocated by angr.
            return None

        return obj.find_segment_containing(addr)

    def find_section_containing(self, addr, skip_pseudo_objects=True):
        """
        Find the section object that the address belongs to.

        :param int addr: The address to test.
        :param bool skip_pseudo_objects: Skip objects that CLE adds during loading.
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Section
        """

        obj = self.find_object_containing(addr, membership_check=False)

        if obj is None:
            return None

        if skip_pseudo_objects and isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a special CLE section
            return None

        return obj.find_section_containing(addr)

    def find_section_next_to(self, addr, skip_pseudo_objects=True):
        """
        Find the next section after the given address.

        :param int addr: The address to test.
        :param bool skip_pseudo_objects: Skip objects that CLE adds during loading.
        :return: The next section that goes after the given address, or None if there is no section after the address,
                 or if section information is not available.
        :rtype: cle.Section
        """

        obj = self.find_object_containing(addr, membership_check=False)

        if obj is None:
            return None

        if skip_pseudo_objects and isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a special CLE section
            return None

        return obj.sections.find_region_next_to(addr)

    def find_symbol(self, thing, fuzzy=False):
        """
        Search for the symbol with the given name or address.

        :param thing:       Either the name or address of a symbol to look up
        :param fuzzy:       Set to True to return the first symbol before or at the given address

        :returns:           A :class:`cle.backends.Symbol` object if found, None otherwise.
        """
        if type(thing) is archinfo.arch_soot.SootAddressDescriptor:
            # Soot address
            return thing.method.fullname
        elif type(thing) is int:
            # address
            if fuzzy:
                so = self.find_object_containing(thing)
                if so is None:
                    return None
                objs = [so]
            else:
                objs = self.all_objects

            for so in objs:
                idx = so.symbols.bisect_key_right(AT.from_mva(thing, so).to_rva()) - 1
                while idx >= 0 and (fuzzy or so.symbols[idx].rebased_addr == thing):
                    if so.symbols[idx].is_import:
                        idx -= 1
                        continue
                    return so.symbols[idx]
        else:
            # name
            for so in self.all_objects:
                if so is self._extern_object:
                    continue
                sym = so.get_symbol(thing)
                if sym is None:
                    continue

                if sym.is_import:
                    if sym.resolvedby is not None:
                        if sym.resolvedby.is_forward and sym.resolvedby.resolvedby is not None:
                            return sym.resolvedby.resolvedby
                        return sym.resolvedby
                else:
                    if sym.is_forward and sym.resolvedby is not None:
                        return sym.resolvedby
                    return sym

            if self._extern_object is not None:
                sym = self.extern_object.get_symbol(thing)
                if sym is not None:
                    return sym

        return None

    @property
    def symbols(self):
        peeks = []
        for so in self.all_objects:
            if so.symbols:
                i = iter(so.symbols)
                n = next(i)
                peeks.append((n, i))
        while peeks:
            element = min(peeks, key=lambda x: x[0].rebased_addr) # if we don't do this it might crash on comparing iterators
            n, i = element
            idx = peeks.index(element)
            yield n
            try:
                peeks[idx] = next(i), i
            except StopIteration:
                peeks.pop(idx)

    def find_all_symbols(self, name, exclude_imports=True, exclude_externs=False, exclude_forwards=True):
        """
        Iterate over all symbols present in the set of loaded binaries that have the given name

        :param name:                The name to search for
        :param exclude_imports:     Whether to exclude import symbols. Default True.
        :param exclude_externs:     Whether to exclude symbols in the extern object. Default False.
        :param exclude_forwards:    Whether to exclude forward symbols. Default True.
        """
        for so in self.all_objects:
            sym = so.get_symbol(name)
            if sym is None:
                continue
            if sym.is_import and exclude_imports:
                continue
            if sym.owner is self._extern_object and exclude_externs:
                continue
            if sym.is_forward and exclude_forwards:
                continue

            yield sym

    def find_plt_stub_name(self, addr):
        """
        Return the name of the PLT stub starting at ``addr``.
        """
        so = self.find_object_containing(addr)
        if so is not None and isinstance(so, MetaELF):
            return so.reverse_plt.get(addr, None)
        return None

    def find_relevant_relocations(self, name):
        """
        Iterate through all the relocations referring to the symbol with the given ``name``
        """
        for so in self.all_objects:
            for reloc in so.relocs:
                if reloc.symbol is not None:
                    if reloc.symbol.name == name:
                        yield reloc

    # Complicated stuff

    def perform_irelative_relocs(self, resolver_func):
        """
        Use this method to satisfy ``IRelative`` relocations in the binary that require execution of loaded code.

        Note that this does NOT handle ``IFunc`` symbols, which must be handled separately. (this could be changed, but
        at the moment it's desirable to support lazy IFunc resolution, since emulation is usually slow)

        :param resolver_func:   A callback function that takes an address, runs the code at that address, and returns
                                the return value from the emulated function.
        """
        for obj in self.all_objects:
            for resolver, dest in obj.irelatives:
                val = resolver_func(resolver)
                if val is not None:
                    obj.memory.pack_word(dest, val)

    def dynamic_load(self, spec):
        """
        Load a file into the address space. Note that the sematics of ``auto_load_libs`` and ``except_missing_libs``
        apply at all times.

        :param spec:    The path to the file to load. May be an absolute path, a relative path, or a name to search in
                        the load path.

        :return:        A list of all the objects successfully loaded, which may be empty if this object was previously
                        loaded. If the object specified in ``spec`` failed to load for any reason, including the file
                        not being found, return None.
        """
        try:
            return self._internal_load(spec)
        except CLEFileNotFoundError as e:
            l.warning("Dynamic load failed: %r", e)
            return None

    def get_loader_symbolic_constraints(self):
        """
        Do not use this method.
        """
        if not self.aslr:
            return []

        try:
            import claripy  # pylint:disable=import-outside-toplevel
        except ImportError:
            claripy = None

        if not claripy:
            l.error("Please install claripy to get symbolic constraints")
            return []
        outputlist = []
        for obj in self.all_objects:
            #TODO Fix Symbolic for tls whatever
            if obj.aslr and isinstance(obj.mapped_base_symbolic, claripy.ast.BV):
                outputlist.append(obj.mapped_base_symbolic == obj.mapped_base)
        return outputlist


    # Private stuff

    @staticmethod
    def _is_linux_loader_name(name):
        """
        ld can have different names such as ld-2.19.so or ld-linux-x86-64.so.2 depending on symlinks and whatnot.
        This determines if `name` is a suitable candidate for ld.
        """
        return 'ld.so' in name or 'ld64.so' in name or 'ld-linux' in name

    def _internal_load(self, *args, preloading=()):
        """
        Pass this any number of files or libraries to load. If it can't load any of them for any reason, it will
        except out. Note that the semantics of ``auto_load_libs`` and ``except_missing_libs`` apply at all times.
		可传递任意数量的文件或库给这个函数进行加载。如果其中任意一个不能正确加载，则函数会非正常退出。
		auto_load_libs和except_missing_libs参数在该函数中会一直有意义

        It will return a list of all the objects successfully loaded, which may be smaller than the list you provided
        if any of them were previously loaded.
		它将返回所有成功加载的对象的列表，该列表可能小于我们提供的希望加载对象的列表，因为它们中的某些可能之前加载了。

        The ``main_binary`` has to come first, followed by any additional libraries to load this round. To create the
        effect of "preloading", i.e. ensuring symbols are resolved to preloaded libraries ahead of any others, pass
        ``preloading`` as a list of identifiers which should be considered preloaded. Note that the identifiers will
        be compared using object identity.
		main_binary应该首先传入，然后是这次需加载的其他库。为了产生preloading的效果，即为了确保符号在任何其他库之前被解析为预加载的库，将“preloading”作为一个标识哪些应该预加载的列表传递进来。
		
        """
        # ideal loading pipeline: 一个理想的加载器应该包含下述内容
        # - load everything, independently and recursively until dependencies are satisfied 可以独立且递归地加载所有内容，直到满足依赖关系为止
        # - resolve symbol-based dependencies 可解决基于符号的依赖性
        # - layout address space, including (as a prerequisite) coming up with the layout for tls and externs 完善的布局地址空间，包括能兼容tls和extern的布局空间（作为先决条件）
        # - map everything into memory 可将所有内容映射到内存中
        # - perform relocations 可完美执行重定位

        # STEP 1
        # Load everything. for each binary, load it in isolation so we end up with a Backend instance. 加载所有内容。对于每个二进制，单独加载它，这样会得到一个backend实例
        # If auto_load_libs is on, do this iteratively until all dependencies is satisfied 如果 auto_load_libs开启，则迭代执行此操作，直到满足所有依赖项。
		
        objects = []
        preload_objects = []
        dependencies = []
        cached_failures = set() # this assumes that the load path is global and immutable by the time we enter this func 这假设在我们进入这个函数时加载路径是全局且不可变的  这个函数是哪个函数？

		# 加载args参数指定中的对象
        for main_spec in args:
            is_preloading = any(spec is main_spec for spec in preloading)  # 对于preloading里的每一项，判断它们是否全在args中，只要有一个在，则返回True
            if self.find_object(main_spec, extra_objects=objects) is not None: # 判断对应的文件是否已经被加载，如果是，则跳过本次循环，
                l.info("Skipping load request %s - already loaded", main_spec)
                continue
            obj = self._load_object_isolated(main_spec) # 否则调用_load_object_isolated加载单个文件.该函数将加载对象以backend实例返回
            objects.append(obj) # 将加载的所有对象添加到objects中
            objects.extend(obj.child_objects)
            dependencies.extend(obj.deps) # 依赖添加到dependencies中

            if self.main_object is None: # 如果self.main_object没有指定，
                # this is technically the first place we can start to initialize things based on platform
                self.main_object = obj # 就将第一个对象obj设置为main_object
                self.memory = Clemory(obj.arch, root=True)  # 创建一个Clemory类的实例，用于初始化内存空间，然后赋值给self.memory

				# 如果self.main_object是ELFCore对象，或者self.main_object没有child_object，那么chk_obj = main_object，否则chk_obj = main_object.child_objects[0]
                chk_obj = self.main_object if isinstance(self.main_object, ELFCore) or not self.main_object.child_objects else self.main_object.child_objects[0]
				# 根据不同文件格式初始化tls（线程本地存储， Thread Local Storage）
                if isinstance(chk_obj, ELFCore):
                    self.tls = ELFCoreThreadManager(self, obj.arch)
                elif isinstance(obj, Minidump):
                    self.tls = MinidumpThreadManager(self, obj.arch)
                elif isinstance(chk_obj, MetaELF):
                    self.tls = ELFThreadManager(self, obj.arch)
                elif isinstance(chk_obj, PE):
                    self.tls = PEThreadManager(self, obj.arch)
                else:
                    self.tls = ThreadManager(self, obj.arch)

            elif is_preloading:
                self.preload_libs.append(obj)
                preload_objects.append(obj)

		# 当设置_auto_load_libs==true且有dependencies时，加载并移除所有 dependencies 里的对象文件，添加到 objects，依赖添加到 dependencies。
	    # 如此一直执行下去直到 dependencies 为空。此时 objects 里就是所有加载对象
        while self._auto_load_libs and dependencies: 
            spec = dependencies.pop(0) # 弹出第一个依赖，如果最后一个弹出了，那么本次流程结束后循环就会结束
            if spec in cached_failures:
                l.debug("Skipping implicit dependency %s - cached failure", spec) # 跳过隐式依赖，因为缓存失败
                continue
            if self.find_object(spec, extra_objects=objects) is not None: # 跳过隐式依赖，因为已经加载
                l.debug("Skipping implicit dependency %s - already loaded", spec)
                continue

            try:
                l.info("Loading %s...", spec)
                obj = self._load_object_isolated(spec)  # loading dependencies 加载依赖
            except CLEFileNotFoundError:
                l.info("... not found")
                cached_failures.add(spec) # 如果加载失败，则将其加入cached_failures，下次不尝试加载了
                if self._except_missing_libs:
                    raise
                continue

            objects.append(obj) # 将加载的所有对象添加到objects中
            objects.extend(obj.child_objects)
            dependencies.extend(obj.deps) # 将依赖的依赖添加到dependencies中

            if type(self.tls) is ThreadManager:   # ... java
                if isinstance(obj, MetaELF):
                    self.tls = ELFThreadManager(self, obj.arch)
                elif isinstance(obj, PE):
                    self.tls = PEThreadManager(self, obj.arch)

        # STEP 1.5
        # produce dependency-ordered list of objects and soname map
		# 生成对象的依赖顺序列表和 so名字的映射？

        ordered_objects = []
        soname_mapping = OrderedDict((obj.provides if not self._ignore_import_version_numbers else obj.provides.rstrip('.0123456789'), obj) for obj in objects if obj.provides)
        seen = set()
        def visit(obj):
            if id(obj) in seen:
                return
            seen.add(id(obj))

            stripped_deps = [dep if not self._ignore_import_version_numbers else dep.rstrip('.0123456789') for dep in obj.deps]
            dep_objs = [soname_mapping[dep_name] for dep_name in stripped_deps if dep_name in soname_mapping]
            for dep_obj in dep_objs:
                visit(dep_obj)

            ordered_objects.append(obj)

        for obj in preload_objects + objects:
            visit(obj)

        # STEP 2
        # Resolve symbol dependencies. Create an unmapped extern object, which may not be used
        # after this step, everything should have the appropriate references to each other and the extern
        # object should have all the space it needs allocated
		# 解析符号依赖，创建一个

        extern_obj = ExternObject(self)

        # tls registration
        for obj in objects:
            self.tls.register_object(obj)

        # link everything
        if self._perform_relocations:
            for obj in ordered_objects:
                l.info("Linking %s", obj.binary)
                sibling_objs = list(obj.parent_object.child_objects) if obj.parent_object is not None else []
                stripped_deps = [dep if not self._ignore_import_version_numbers else dep.rstrip('.0123456789') for dep in obj.deps]
                dep_objs = [soname_mapping[dep_name] for dep_name in stripped_deps if dep_name in soname_mapping]
                main_objs = [self.main_object] if self.main_object is not obj else []
                for reloc in obj.relocs:
                    reloc.resolve_symbol(main_objs + preload_objects + sibling_objs + dep_objs + [obj], extern_object=extern_obj)

        # if the extern object was used, add it to the list of objects we're mapping
        # also add it to the linked list of extern objects
        if extern_obj.map_size:
            # resolve the extern relocs this way because they may produce more relocations as we go
            i = 0
            while i < len(extern_obj.relocs):
                extern_obj.relocs[i].resolve_symbol(objects, extern_object=extern_obj)
                i += 1

            objects.append(extern_obj)
            ordered_objects.insert(0, extern_obj)
            extern_obj._next_object = self._extern_object
            self._extern_object = extern_obj

            extern_obj._finalize_tls()
            self.tls.register_object(extern_obj)

        # STEP 3
        # Map everything to memory 映射所有内容到内存
        for obj in objects:
            self._map_object(obj)

        # STEP 4
        # Perform relocations  重定位
        if self._perform_relocations:
            for obj in ordered_objects:
                obj.relocate()

        # Step 5
        # Insert each object into the appropriate mappings for lookup by name
		
        for obj in objects:
            self.requested_names.update(obj.deps)
            for ident in self._possible_idents(obj):
                self._satisfied_deps[ident] = obj

            if obj.provides is not None:
                self.shared_objects[obj.provides] = obj

        return objects

    def _load_object_isolated(self, spec): # 单独加载一个对象
        """
        Given a partial specification of a dependency, this will return the loaded object as a backend instance.
        It will not touch any loader-global data.
		给定依赖关系的部分规范，这会将加载的对象作为backend实例返回，它不会触及任何loader的全局数据
        """
        # STEP 1: identify file 识别文件
        if isinstance(spec, Backend): # 如果spec是Backend对象
            return spec
        elif hasattr(spec, 'read') and hasattr(spec, 'seek'): # 如果spec是一个流
            binary_stream = spec
            binary = None
            close = False
        elif type(spec) in (bytes, str): # 如果spec是一个字符串或字节对象，则调用_search_load_path去获取完整的文件路径
            binary = self._search_load_path(spec) # this is allowed to cheat and do partial static loading
            l.debug("... using full path %s", binary)
            binary_stream = open(binary, 'rb') # 然后打开文件，得到流
            close = True
        else:
            raise CLEError("Bad library specification: %s" % spec)

        try:
            # STEP 2: collect options 收集选项
            if self.main_object is None: # 如果main_object为空
                options = dict(self._main_opts)
            else:   # 否则，遍历生成器 _possible_idents，获取所有可能用于描述给定spec的识别符ident，
                for ident in self._possible_idents(binary_stream if binary is None else binary): # also allowed to cheat
                    if ident in self._lib_opts: # 然后取出_lib_opts
                        options = dict(self._lib_opts[ident])
                        break
                else:
                    options = {}

            # STEP 3: identify backend 识别 Backend
            backend_spec = options.pop('backend', None) # 从选项中获取backend_spec
            backend_cls = self._backend_resolver(backend_spec) # 调用_backend_resolver解析得到对应的后端类backend_cls
            if backend_cls is None: # 如果 backend_cls 为空，则调用函数_static_backend获取
                backend_cls = self._static_backend(binary_stream if binary is None else binary)
            if backend_cls is None: # 如果backend_cls还是空，则抛出异常
                raise CLECompatibilityError("Unable to find a loader backend for %s.  Perhaps try the 'blob' loader?" % spec)

            # STEP 4: LOAD! 加载，创建backend_cls类的实例
            l.debug("... loading with %s", backend_cls)

            result = backend_cls(binary, binary_stream, is_main_bin=self.main_object is None, loader=self, **options)
            result.close()
            return result
        finally:
            if close:
                binary_stream.close()

    def _map_object(self, obj: 'Backend'):
        """
        This will integrate the object into the global address space, but will not perform relocations.
        """
        obj_size = obj.max_addr - obj.min_addr + 1

        if obj.pic:
            if obj._custom_base_addr is not None and self._is_range_free(obj._custom_base_addr, obj_size):
                base_addr = obj._custom_base_addr
            elif obj.linked_base and self._is_range_free(obj.linked_base, obj_size):
                base_addr = obj.linked_base
            elif not obj.is_main_bin:
                base_addr = self._find_safe_rebase_addr(obj_size)
            else:
                l.warning("The main binary is a position-independent executable. "
                          "It is being loaded with a base address of 0x400000.")
                base_addr = 0x400000

            obj.rebase(base_addr)
        else:
            if obj._custom_base_addr is not None and obj.linked_base != obj._custom_base_addr and not isinstance(obj, Blob):
                l.warning("%s: base_addr was specified but the object is not PIC. "
                          "specify force_rebase=True to override", obj.binary_basename)
            base_addr = obj.linked_base
            if not self._is_range_free(obj.linked_base, obj_size):
                raise CLEError("Position-DEPENDENT object %s cannot be loaded at %#x"% (obj.binary, base_addr))

        assert obj.mapped_base >= 0

        if obj.has_memory:
            assert obj.min_addr <= obj.max_addr
            l.info("Mapping %s at %#x", obj.binary, base_addr)
            self.memory.add_backer(base_addr, obj.memory)
        obj._is_mapped = True
        key_bisect_insort_right(self.all_objects, obj, keyfunc=lambda o: o.min_addr)

    # Address space management

    def _find_safe_rebase_addr(self, size):
        """
        Return a "safe" virtual address to map an object of size ``size``, i.e. one that won't
        overlap with anything already loaded.
        """
        # this assumes that self.main_object exists, which should... definitely be safe
        if self.main_object.arch.bits < 32 or self.main_object.max_addr >= 2**(self.main_object.arch.bits-1):
            # HACK: On small arches, we should be more aggressive in packing stuff in.
            gap_start = 0
        else:
            gap_start = ALIGN_UP(self.main_object.max_addr + 1, self._rebase_granularity)
        for o in self.all_objects:
            if gap_start + size <= o.min_addr:
                break
            else:
                gap_start = ALIGN_UP(o.max_addr + 1, self._rebase_granularity)

        if gap_start + size > 2**self.main_object.arch.bits:
            # this may happen when loading an ELF core whose main object may occupy a large range of memory addresses
            # with large unoccupied holes left in the middle
            # we fall back to finding unoccupied holes
            for this_seg, next_seg in zip(self.main_object.segments.raw_list, self.main_object.segments.raw_list[1:]):
                gap_start = ALIGN_UP(this_seg.vaddr + this_seg.memsize, self._rebase_granularity)
                gap = next_seg.vaddr - gap_start
                if gap >= size:
                    break
            else:
                raise CLEOperationError("Ran out of room in address space")

        return gap_start

    def _is_range_free(self, va, size):
        # self.main_object should not be None here
        if va < 0 or va + size > 2**self.main_object.arch.bits:
            return False

        for o in self.all_objects:
            if o.min_addr <= va <= o.max_addr or va <= o.min_addr < va + size:
                return False

        return True

    # Functions of the form "use some heuristic to tell me about this spec"

    def _search_load_path(self, spec):
        """
        This will return the most likely full path that could satisfy the given partial specification.

        It will prefer files of a known filetype over files of an unknown filetype.
        """
        # this could be converted to being an iterator pretty easily
        for path in self._possible_paths(spec):
            if self.main_object is not None:
                backend_cls = self._static_backend(path)
                if backend_cls is None:
                    continue
                # If arch of main object is Soot ...
                if isinstance(self.main_object.arch, ArchSoot):
                    # ... skip compatibility check, since it always evaluates to false
                    # with native libraries (which are the only valid dependencies)
                    return path
                if not backend_cls.check_compatibility(path, self.main_object):
                    continue

            return path

        raise CLEFileNotFoundError("Could not find file %s" % spec)

    def _possible_paths(self, spec):
        """
        This iterates through each possible path that could possibly be used to satisfy the specification.

        The only check performed is whether the file exists or not.
        """
        dirs = []
        dirs.extend(self._custom_ld_path)                   # if we say dirs = blah, we modify the original

        if self.main_object is not None:
            # add path of main binary
            if self.main_object.binary is not None:
                dirs.append(os.path.dirname(self.main_object.binary))
            # if arch of main_object is Soot ...
            is_arch_soot = isinstance(self.main_object.arch, ArchSoot)
            if is_arch_soot:
                # ... extend with load path of native libraries
                dirs.extend(self.main_object.extra_load_path)
                if self._use_system_libs:
                    l.debug("Path to system libraries (usually added as dependencies of JNI libs) needs "
                            "to be specified manually, by using the custom_ld_path option.")
            # add path of system libraries
            if self._use_system_libs and not is_arch_soot:
                # Ideally this should be taken into account for each shared
                # object, not just the main object.
                dirs.extend(self.main_object.extra_load_path)
                if sys.platform.startswith('linux'):
                    dirs.extend(self.main_object.arch.library_search_path())
                elif sys.platform.startswith('openbsd'):
                    dirs.extend(self.main_object.arch.library_search_path())
                    dirs.extend(['/usr/local/lib', '/usr/X11R6/lib'])
                elif sys.platform == 'win32':
                    native_dirs = os.environ['PATH'].split(';')

                    # simulate the wow64 filesystem redirect, working around the fact that WE may be impacted by it as
                    # a 32-bit python process.......
                    python_is_32bit = platform.architecture()[0] == '32bit'
                    guest_is_32bit = self.main_object.arch.bits == 32

                    if python_is_32bit != guest_is_32bit:
                        redirect_dir = os.path.join(os.environ['SystemRoot'], 'system32').lower()
                        target_dir = os.path.join(os.environ['SystemRoot'], 'SysWOW64' if guest_is_32bit else 'sysnative')
                        i = 0
                        while i < len(native_dirs):
                            if native_dirs[i].lower().startswith(redirect_dir):
                                # replace the access to System32 with SysWOW64 or sysnative
                                native_dirs[i] = target_dir + native_dirs[i][len(target_dir):]
                            i += 1

                    dirs.extend(native_dirs)

        dirs.append('.')


        if self._case_insensitive:
            spec = spec.lower()

        for libdir in dirs:
            if self._case_insensitive:
                insensitive_path = self._path_insensitive(os.path.join(libdir, spec))
                if insensitive_path is not None:
                    yield os.path.realpath(insensitive_path)
            else:
                fullpath = os.path.realpath(os.path.join(libdir, spec))
                if os.path.exists(fullpath):
                    yield fullpath

            if self._ignore_import_version_numbers:
                try:
                    for libname in os.listdir(libdir):
                        ilibname = libname.lower() if self._case_insensitive else libname
                        if ilibname.strip('.0123456789') == spec.strip('.0123456789'):
                            yield os.path.realpath(os.path.join(libdir, libname))
                except (IOError, OSError): pass

    @classmethod
    def _path_insensitive(cls, path):
        """
        Get a case-insensitive path for use on a case sensitive system, or return None if it doesn't exist.

        From https://stackoverflow.com/a/8462613
        """
        if path == '' or os.path.exists(path):
            return path
        base = os.path.basename(path)  # may be a directory or a file
        dirname = os.path.dirname(path)
        suffix = ''
        if not base:  # dir ends with a slash?
            if len(dirname) < len(path):
                suffix = path[:len(path) - len(dirname)]
            base = os.path.basename(dirname)
            dirname = os.path.dirname(dirname)
        if not os.path.exists(dirname):
            dirname = cls._path_insensitive(dirname)
            if not dirname:
                return None
        # at this point, the directory exists but not the file
        try:  # we are expecting dirname to be a directory, but it could be a file
            files = os.listdir(dirname)
        except OSError:
            return None
        baselow = base.lower()
        try:
            basefinal = next(fl for fl in files if fl.lower() == baselow)
        except StopIteration:
            return None
        if basefinal:
            return os.path.join(dirname, basefinal) + suffix
        else:
            return None

    def _possible_idents(self, spec, lowercase=False):
        """
        This iterates over all the possible identifiers that could be used to describe the given specification.
		这将迭代
        """
        if isinstance(spec, Backend):
            if spec.provides is not None:
                yield spec.provides
                if self._ignore_import_version_numbers:
                    yield spec.provides.rstrip('.0123456789')
            if spec.binary:
                yield spec.binary
                yield os.path.basename(spec.binary)
                yield os.path.basename(spec.binary).split('.')[0]
                if self._ignore_import_version_numbers:
                    yield os.path.basename(spec.binary).rstrip('.0123456789')
        elif hasattr(spec, 'read') and hasattr(spec, 'seek'):
            backend_cls = self._static_backend(spec, ignore_hints=True)
            if backend_cls is not None:
                soname = backend_cls.extract_soname(spec)
                if soname is not None:
                    yield soname
                    if self._ignore_import_version_numbers:
                        yield soname.rstrip('.0123456789')
        elif type(spec) in (bytes, str):
            yield spec
            yield os.path.basename(spec)
            yield os.path.basename(spec).split('.')[0]
            if self._ignore_import_version_numbers:
                yield os.path.basename(spec).rstrip('.0123456789')

            if os.path.exists(spec):
                backend_cls = self._static_backend(spec, ignore_hints=True)
                if backend_cls is not None:
                    soname = backend_cls.extract_soname(spec)
                    if soname is not None:
                        yield soname
                        if self._ignore_import_version_numbers:
                            yield soname.rstrip('.0123456789')

        if not lowercase and (sys.platform == 'win32' or self._case_insensitive):
            for name in self._possible_idents(spec, lowercase=True):
                yield name.lower()

    def _static_backend(self, spec, ignore_hints=False):
        """
        Returns the correct loader for the file at `spec`.
        Returns None if it's a blob or some unknown type.
        TODO: Implement some binwalk-like thing to carve up blobs automatically
		
		返回spec指定文件对应的正确的loader。当spec是一个blob或者一些未知的类型时，返回None
        """

        if not ignore_hints:
            for ident in self._possible_idents(spec):
                try:
                    return self._backend_resolver(self._lib_opts[ident]['backend'])
                except KeyError:
                    pass

        with stream_or_path(spec) as stream:
            for rear in ALL_BACKENDS.values():
                if rear.is_default and rear.is_compatible(stream): # 函数is_compatible()用于判断对象文件是否属于该后端所操作的对象，判断方法是二进制特征匹配，例如ELF文件：if identstring.startswith('x7fELF')
                    return rear

        return None

    @staticmethod
    def _backend_resolver(backend, default=None):
        if isinstance(backend, type) and issubclass(backend, Backend): # 如果backend是Backend的子类，则直接返回
            return backend
        elif backend in ALL_BACKENDS: # 如果backend属于ALL_BACKENDS中的一个,则返回字典中的对应值。ALL_BACKENDS是一个全局字典，里面保存了所有通过函数register_backend(name,cls)注册的后端
            return ALL_BACKENDS[backend]
        elif backend is None: # 如果backend==None，返回default（None）
            return default
        else: # 否则抛出异常
            raise CLEError('Invalid backend: %s' % backend)


from .errors import CLEError, CLEFileNotFoundError, CLECompatibilityError, CLEOperationError
from .memory import Clemory
from .backends import MetaELF, ELF, PE, ELFCore, Minidump, Blob, ALL_BACKENDS, Backend
from .backends.tls import ThreadManager, ELFThreadManager, PEThreadManager, ELFCoreThreadManager, MinidumpThreadManager, TLSObject
from .backends.externs import ExternObject, KernelObject
from .utils import stream_or_path
